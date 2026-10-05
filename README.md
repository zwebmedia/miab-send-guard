# miab-send-guard

Per-account outbound send limits for [Mail-in-a-Box](https://mailinabox.email/) (MIAB), with an automatic lock or pause in seconds, and a public, masked JSON status you can feed into any monitoring or trend tracking.

> Not affiliated with or endorsed by the Mail-in-a-Box project. It works with MIAB's standard Postfix/Dovecot setup and uses MIAB's own management CLI.

## Why this exists

If one mailbox password leaks (a phished user, a reused password, a script with a hard-coded credential), whoever has it can send mail through your server as that user, at machine speed. Within minutes your server's IP address can end up on public blocklists. After that, other mail servers reject or junk **all** of your outgoing mail, including your legitimate business mail, and getting delisted is slow and manual.

For a business that depends on its mail server, that is devastating, and the cost of a false alarm (one password reset) is tiny compared with the cost of a blocklisting. This tool is built on that trade-off: **act first, investigate after.**

## What it does

- Counts messages per authenticated account from Postfix's mail log, continuously (a systemd service, not cron, so detection takes seconds rather than minutes).
- Enforces three limits per account: **per hour**, **per day**, and **burst** (N messages in any rolling window, default 10 in 5 minutes).
- On a breach, takes one of two actions, chosen per account:
  - **`rotate`**: replaces the password with a random one nobody knows. Complete lockout, and the account needs a new password everywhere it is used.
  - **`pause`**: blocks *sending only* for N hours. The password is unchanged, reading mail over IMAP keeps working, and sending resumes by itself. Meant for accounts whose password is baked into many places (monitoring alerts, backup scripts, an AI/automation agent) where a reset is expensive.
- Publishes a **public, masked JSON status** file (hourly/daily counts, limits, countdowns, paused/locked state) that another server can import for trends.
- **Checks itself:** if a Mail-in-a-Box upgrade silently removes the Postfix rule that enforces pauses, it notices within a minute and falls back to rotating the password, so a "paused" account is never left unprotected.

Standard library only; one Python file.

## Requirements

- Mail-in-a-Box (Postfix with SASL submission on port 587, Dovecot). Developed and tested on Postfix 3.6.4.
- Postfix 2.11 or later (for `check_sasl_access`; used by `pause`).
- Python 3.8+, systemd, root access.

## How it works

1. The daemon tails `/var/log/mail.log` and counts lines containing `sasl_username=`. Postfix writes one such line for each message accepted from a logged-in user.
2. After each new message it compares that account's counts with its limits (hour and day are calendar windows in the server's local time; burst is rolling).
3. On a breach it runs the account's action:
   - `rotate`: calls `management/cli.py user password <email> <random>` in your Mail-in-a-Box checkout.
   - `pause`: adds the address to `/etc/postfix/sasl_paused` and recompiles it with `postmap`. Postfix consults that table through `check_sasl_access` and answers new send attempts with `550 5.7.1 Sending from this account is paused until ...`. A pause ends by itself, or earlier with `resume`.
4. Every few seconds it atomically rewrites the status JSON.

A pause answers with a **permanent 550**, not a temporary 450, on purpose: a 450 would make clients queue the mail and retry, and everything would be released in one burst when the pause ends, tripping the limit again. The cost is that mail sent during a pause is **lost, not delayed**. Mail that Postfix had already accepted before the pause (the burst that triggered it) is not affected; inspect it with `postqueue -p`.

## Install

```bash
# 1. Get the code
git clone https://github.com/<you>/miab-send-guard /opt/miab-send-guard
cd /opt/miab-send-guard

# 2. Configure (optional: everything has a default). See "Configuration".
cp config.example.json config.json && nano config.json

# 3. Create the (empty) pause list. It must exist before Postfix refers to it.
sudo python3 watch.py init

# 4. Tell Postfix to consult it. This PREPENDS the rule to your current list,
#    because Mail-in-a-Box's list starts with permit_sasl_authenticated, which
#    would otherwise approve every logged-in user before the rule could run.
#    Run it ONCE.
T=$(postconf -h default_database_type) && \
sudo postconf -e "smtpd_recipient_restrictions=check_sasl_access $T:/etc/postfix/sasl_paused, $(postconf -h smtpd_recipient_restrictions)" && \
sudo postfix check && sudo systemctl reload postfix && \
postconf smtpd_recipient_restrictions

# 5. Install and start the service (edit the paths in the unit if you installed elsewhere)
sudo cp mail-watch.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now mail-watch.service
```

Verify the pause really blocks before you rely on it, using a throwaway account that you can send from in webmail:

```bash
sudo python3 watch.py pause test@example.com 0.05   # 3 minutes
# try to send from that account: it must fail with "paused until ..."
sudo python3 watch.py resume test@example.com        # then send again: it must work
```

If you only use the `rotate` action you can skip steps 3 and 4.

## Configuration

`config.json` next to `watch.py` (or the path in `MAIL_GUARD_CONFIG`). Every key is optional; see `config.example.json`.

| Key | Default | Meaning |
|---|---|---|
| `default_limits` | `hour 10, day 50, burst 10 in 300 s, action rotate, pause_hours 8` | Limits for every account |
| `overrides` | `{}` | Per-account limits, keyed by full lowercase address; unspecified keys inherit the defaults |
| `mask` | `partial`, keep 2 | How addresses appear in the public JSON (see "Masking") |
| `json_out` | `/home/user-data/www/default/mail-stats.json` | Where the status file is written; `""` disables publishing |
| `log_file` | `/var/log/mail.log` | Postfix log to tail |
| `sasl_map` | `/etc/postfix/sasl_paused` | Postfix access table for pauses |
| `miab_dir` | `/root/mailinabox` | Mail-in-a-Box checkout (for `rotate`) |
| `pause_reply` | `550 5.7.1 Sending from this account is paused until {until} (server time)` | What a paused sender is told |
| `salt` | *(generated into `salt.txt`)* | Secret used for hashed ids; keep it private |

There is deliberately **no exemption list**. An account that sends a lot (alerts, an automation agent) gets its own, higher limits and, ideally, `pause` instead of `rotate`, but it keeps a burst limit, because the busiest account is the most valuable one to a thief.

Choosing limits: look at what each account really sends first (`grep sasl_username= /var/log/mail.log`), then set limits somewhat above the legitimate peak.

## Day-to-day commands

```bash
sudo python3 watch.py pause   alerts@example.com 8   # pause sending now (default 8 h)
sudo python3 watch.py resume  alerts@example.com     # release now; counters restart from zero
sudo python3 watch.py status                         # who is paused, and for how long
tail /opt/miab-send-guard/watch.log                  # PAUSE / RESUME / LOCK lines, with the reason
```

`resume` restarts the account's counters from zero. Otherwise the burst you just reviewed would immediately count against it again.

If a `rotate` lock hits a legitimate account: set a new password in the Mail-in-a-Box admin panel (not on the command line), then update every client and script that uses it. A lock is not repeated for the same account on the same day.

## Mail-in-a-Box upgrades: the fallback

Mail-in-a-Box rewrites its managed Postfix settings whenever it is upgraded, and `smtpd_recipient_restrictions` is one of them. After an upgrade the `check_sasl_access` rule can be gone **without any error**. If nothing noticed, pausing would still be logged and shown as `paused: true`, yet Postfix would keep delivering that account's mail: protection silently off.

So the daemon checks once a minute that the rule is present:

- It logs `PAUSE-RULE present` / `PAUSE-RULE MISSING` whenever the state changes.
- It publishes `"pause_rule_active": true|false` at the top level of the status JSON (field reference below), so your external monitoring can alert on `false`.
- **While the rule is missing, a breach by a `pause` account falls back to `rotate`.** The log line says why. Protection beats convenience: the account is locked out, and you do the big password reset that `pause` was meant to avoid, but only when a breach happens at the same time as a lost rule.

After every Mail-in-a-Box upgrade, check, and restore if needed by repeating install step 4:

```bash
postconf smtpd_recipient_restrictions | grep -c check_sasl_access   # 1 = present, 0 = missing
```

`rotate` accounts do not depend on Postfix and are unaffected.

## Public JSON status

Mail-in-a-Box serves everything under `/home/user-data/www/default/` over HTTPS, so by default the status appears at `https://<your box hostname>/mail-stats.json`: no authentication, readable by anyone. That is deliberate (a remote monitor can poll it without credentials), and the reason addresses are masked.

```json
{
  "generated_at": "2026-10-05T05:52:39+00:00",
  "pause_rule_active": true,
  "hourly_limit": 10,
  "daily_limit": 50,
  "hour_resets_in": {"hours": 0, "minutes": 7, "label": "0h 7m"},
  "day_resets_in":  {"hours": 12, "minutes": 7, "label": "12h 7m"},
  "accounts": [
    {
      "account_id": "5d6d83604155",
      "email_masked": "al***@example.com",
      "hour_count": 4, "day_count": 31, "peak_hour_count": 12, "burst_count": 1,
      "hour_limit": 20, "day_limit": 100, "burst_limit": 10, "burst_seconds": 300,
      "action": "pause",
      "locked": false, "locked_at": null,
      "paused": false, "paused_until": null, "paused_resumes_in": null
    }
  ]
}
```

Only accounts with activity today (or currently paused) are listed. Times are UTC; "resets in" is computed against the server's local midnight and hour boundary.

### What the fields mean

Per account:

| Field | Meaning |
|---|---|
| `account_id` | Stable salted-hash id. Use it as the key for history; it reveals no address. |
| `email_masked` | The address as obfuscated by your `mask` setting. |
| `hour_count` / `day_count` | Messages sent in the current calendar hour / day (server local time). |
| `peak_hour_count` | The busiest single hour so far today. |
| `burst_count` | Messages in the last `burst_seconds` seconds. |
| `hour_limit` / `day_limit` / `burst_limit` / `burst_seconds` | This account's limits. |
| `action` | **Policy, not state.** What *will* happen if the account breaches a limit: `pause` or `rotate`. It is configuration and does not change when something happens. |
| `locked` / `locked_at` | `true` only if the password was **rotated** today, and when. |
| `paused` | `true` only while sending is **actually blocked**. |
| `paused_until` / `paused_resumes_in` | End time (UTC) and countdown of an active pause; `null` when not paused. |

Top level of the file:

| Field | Meaning |
|---|---|
| `generated_at` | When the snapshot was written (UTC). Alert if it goes stale: the watcher is not running. |
| `pause_rule_active` | `true` if Postfix currently has the `check_sasl_access` rule that enforces pauses (the watcher re-checks once a minute). `false` means the rule is **missing**, usually after a Mail-in-a-Box upgrade, so pauses are **not enforced** and `pause` accounts fall back to password rotation on a breach. Restore it by repeating install step 4, then it returns to `true` within a minute. See "Mail-in-a-Box upgrades: the fallback". |
| `hourly_limit` / `daily_limit` | The default limits (accounts with overrides carry their own, see per-account fields). |
| `hour_resets_in` / `day_resets_in` | Time until the next calendar hour / day starts, when those counters restart. |

**Alert on state, not policy:** raise an alarm when `paused` or `locked` is `true`, or when `pause_rule_active` is `false`. An account showing `"action": "pause"` with `"paused": false` is healthy: it is sending normally and is merely configured to be paused rather than locked if it ever breaches.

### Logging it somewhere else

Poll the file from any other server and store it. `examples/import_stats.py` is a ready-to-run example (stdlib only) that keeps one row per account per day in SQLite:

```bash
50 23 * * *  python3 /path/import_stats.py https://box.example.com/mail-stats.json /path/stats.db
```

Key your history by `account_id`, not the masked address: it is stable and unique per account. Track `day_count` against `day_limit` and `peak_hour_count` against `hour_limit` over time to see accounts creeping toward their limits, and alert on `pause_rule_active == false`.

## Masking

Because the file is public, addresses are obfuscated. Choose how in `config.json`:

| `mask.mode` | Result for `alice@example.com` | Use when |
|---|---|---|
| `partial` (default) | `al***@example.com` (`keep` = characters shown; a short name never shows in full) | You recognise your own accounts at a glance |
| `hash` | `3fa9c21b@example.com` (`hash_length` characters of a salted SHA-256) | Stable pseudonyms; the person cannot be guessed from the output |
| `domain_only` | `***@example.com` | You only care about volume per domain |
| `none` | `alice@example.com` | The file is not public (see below) |

`"keep_domain": false` also hides the domain (`***@***`).

Notes:

- `account_id` is **always** a salted hash of the address, never the address. The salt comes from `salt` in the config, or a random one generated once into `salt.txt` (mode 0600). Without the salt, ids cannot be reversed by guessing addresses, so keep it private and keep it out of git (`.gitignore` already does).
- `partial` leaks structure: `al***@example.com` tells a stranger a mailbox called `al...` exists. For small teams prefer `hash` or `domain_only`.
- Counts reveal when an account is active. If that is sensitive, set `json_out` to a location you protect (for example behind HTTP basic auth in your web server) and let your monitor authenticate.
- For a scheme the modes do not cover, edit the `mask()` function in `watch.py`. It is a dozen lines and the only place addresses are formatted.

## Limitations (read these)

- **It counts messages, not recipients.** One message to 500 recipients counts as one send. Consider also lowering Postfix's `smtpd_recipient_limit`.
- Only mail submitted by a logged-in user is counted. Inbound mail and local system mail are not.
- Hour and day windows are calendar windows in the server's local time, so an account can send up to the hourly limit just before and just after an hour boundary. The burst limit covers the rolling case.
- **`rotate` passes the new random password to Mail-in-a-Box's CLI as a command-line argument,** so for a moment it is visible to other local users (`ps`). On a server where only root has a shell this does not matter; it does if you give shell accounts to other people.
- `pause` loses mail sent during the pause (see above), and does not affect messages already accepted into the Postfix queue.
- The daemon seeds its counters from the current `mail.log` when it starts, not from rotated logs.
- A `rotate` lock is not repeated for the same account later the same day.
- Written for Mail-in-a-Box's layout. Other Postfix setups need different paths and a different rotate step.
- **Test it on a throwaway account before trusting it,** especially after Postfix or Mail-in-a-Box upgrades. No warranty (see `LICENSE`).

## Tests

```bash
python3 -m unittest discover -s tests -v
```

The tests mock Postfix and the Mail-in-a-Box CLI; no mail server is needed.

## Uninstall

```bash
sudo systemctl disable --now mail-watch.service && sudo rm /etc/systemd/system/mail-watch.service
# remove the "check_sasl_access ...sasl_paused," prefix from smtpd_recipient_restrictions:
postconf smtpd_recipient_restrictions     # then set it back with: sudo postconf -e "smtpd_recipient_restrictions=<value without the prefix>"
sudo systemctl reload postfix
sudo rm -f /etc/postfix/sasl_paused /etc/postfix/sasl_paused.db
```

## License

MIT License. Love it, hate it, or fork it! See `LICENSE`.
