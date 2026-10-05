#!/usr/bin/env python3
"""
miab-send-guard: per-account outbound send limits for Mail-in-a-Box.

Watches Postfix's mail log and, within seconds of an authenticated account
crossing its hourly, daily or burst limit, either

  rotate : replaces the account's password with a random one (full lockout), or
  pause  : blocks SENDING ONLY for N hours (password unchanged, IMAP keeps
           working, sending resumes by itself).

It also publishes a masked JSON status file that another server can import
for trend tracking. Standard library only.

DAEMON (systemd):      python3 watch.py
COMMANDS (as root):
  python3 watch.py init                create/refresh the Postfix pause map
  python3 watch.py pause EMAIL [HRS]   pause sending now (default 8 h)
  python3 watch.py resume EMAIL        end a pause now, counters restart from zero
  python3 watch.py status              list paused accounts

Configuration: config.json next to this script (see config.example.json), or
the path in the MAIL_GUARD_CONFIG environment variable. Everything has a default.

How a pause is enforced: paused addresses are written to a Postfix access table
(default /etc/postfix/sasl_paused) that Postfix consults via check_sasl_access
(Postfix 2.11+). The reply is a permanent 550, so mail sent during a pause is
refused, not queued: nothing piles up and nothing is released in one burst when
the pause ends. The cost is that mail sent during a pause is lost, not delayed.

Safety net: every minute the daemon checks that Postfix still has the pause
rule (a Mail-in-a-Box upgrade can remove it). If it is missing, a breach by a
"pause" account falls back to rotating the password, so the account is never
left unprotected. The state is logged (PAUSE-RULE) and published as
pause_rule_active in the JSON.
"""
import re
import sys
import json
import hashlib
import secrets
import subprocess
import datetime
import os
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.environ.get("MAIL_GUARD_CONFIG", os.path.join(BASE_DIR, "config.json"))
STATE_FILE = os.path.join(BASE_DIR, "state.json")    # accounts rotated today
CTL_FILE = os.path.join(BASE_DIR, "paused.json")     # pauses and counter resets
SALT_FILE = os.path.join(BASE_DIR, "salt.txt")       # generated once, mode 0600

DEFAULTS = {
    "log_file": "/var/log/mail.log",
    # Mail-in-a-Box serves this directory over HTTPS, so the file is PUBLIC at
    # https://<box hostname>/mail-stats.json. Set to "" to disable publishing.
    "json_out": "/home/user-data/www/default/mail-stats.json",
    "sasl_map": "/etc/postfix/sasl_paused",
    "miab_dir": "/root/mailinabox",
    "poll_seconds": 2,
    "write_every_seconds": 5,
    "pause_reply": "550 5.7.1 Sending from this account is paused until {until} (server time)",
    # hour / day: per calendar hour / day (server local time).
    # burst: messages in any rolling window of burst_seconds.
    # action: "rotate" or "pause".
    "default_limits": {"hour": 10, "day": 50, "burst": 10, "burst_seconds": 300,
                       "action": "rotate", "pause_hours": 8},
    # Per-account limits, keyed by full lowercase address; unspecified keys
    # inherit from default_limits.
    "overrides": {},
    # How addresses appear in the PUBLIC json. See README, "Masking".
    #   partial     ab***@example.com   (keep = characters of the local part shown)
    #   hash        3fa9c21b@example.com (salted hash; stable, not reversible)
    #   domain_only ***@example.com
    #   none        the real address
    "mask": {"mode": "partial", "keep": 2, "keep_domain": True, "hash_length": 8},
    "salt": "",   # secret for hashes; if empty a random one is created in salt.txt
}

# Active settings (filled by apply_config).
LOG_FILE = JSON_OUT = SASL_MAP = CLI_DIR = None
POLL_SECONDS = WRITE_EVERY_SECONDS = 0
PAUSE_REPLY = ""
DEFAULT_LIMITS = {}
OVERRIDES = {}
MASK = {}
SALT = ""
CLI = "management/cli.py"

SASL_RE = re.compile(r"^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\S*\s.*sasl_username=(\S+)")

# Rolling list of (epoch_seconds, user) events, trimmed to the last 24h.
events = []

# Pauses and counter resets, cached by file mtime.
CTL = {"paused": {}, "floor": {}}
_ctl_mtime = None
_rule = {"ok": None, "checked": 0.0}


# ---------------------------------------------------------------- configuration

def _merge(base, extra):
    out = dict(base)
    for k, v in (extra or {}).items():
        out[k] = {**base[k], **v} if isinstance(base.get(k), dict) and isinstance(v, dict) else v
    return out


def get_salt(configured):
    if configured:
        return configured
    if os.path.exists(SALT_FILE):
        with open(SALT_FILE) as f:
            return f.read().strip()
    salt = secrets.token_hex(16)
    fd = os.open(SALT_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(salt)
    return salt


def apply_config(user_cfg=None):
    """Merge user settings over DEFAULTS and set the module-level settings."""
    global LOG_FILE, JSON_OUT, SASL_MAP, CLI_DIR, POLL_SECONDS, WRITE_EVERY_SECONDS
    global PAUSE_REPLY, DEFAULT_LIMITS, OVERRIDES, MASK, SALT
    cfg = _merge(DEFAULTS, user_cfg)
    LOG_FILE, JSON_OUT, SASL_MAP = cfg["log_file"], cfg["json_out"], cfg["sasl_map"]
    CLI_DIR, PAUSE_REPLY = cfg["miab_dir"], cfg["pause_reply"]
    POLL_SECONDS, WRITE_EVERY_SECONDS = cfg["poll_seconds"], cfg["write_every_seconds"]
    DEFAULT_LIMITS = cfg["default_limits"]
    OVERRIDES = {k.lower(): v for k, v in cfg["overrides"].items()}
    MASK = cfg["mask"]
    SALT = cfg["salt"]
    return cfg


def load_config_file():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            return json.load(f)
    return {}


apply_config({})


def limits_for(user):
    lim = dict(DEFAULT_LIMITS)
    lim.update(OVERRIDES.get(user.lower(), {}))
    return lim


# ---------------------------------------------------------------- masking

def account_id(email):
    """Stable, salted, non-reversible id: use this as the key when importing
    the public JSON elsewhere."""
    return hashlib.sha256(f"{SALT}:{email.lower()}".encode()).hexdigest()[:12]


def mask(email):
    """How an address appears in the public JSON. Edit this function for a
    scheme the config modes do not cover."""
    local, _, domain = email.partition("@")
    mode = MASK.get("mode", "partial")
    if mode == "none":
        shown = local
    elif mode == "hash":
        shown = hashlib.sha256(f"{SALT}:{email.lower()}".encode()).hexdigest()[:int(MASK.get("hash_length", 8))]
    elif mode == "domain_only":
        shown = "***"
    else:  # partial
        keep = min(int(MASK.get("keep", 2)), max(len(local) - 1, 0))  # never reveal a whole short name
        shown = local[:keep] + "***"
    if not domain:
        return shown
    return f"{shown}@{domain if MASK.get('keep_domain', True) else '***'}"


# ---------------------------------------------------------------- control file

def load_ctl():
    if os.path.exists(CTL_FILE):
        with open(CTL_FILE) as f:
            data = json.load(f)
        data.setdefault("paused", {})
        data.setdefault("floor", {})
        return data
    return {"paused": {}, "floor": {}}


def save_ctl(data):
    tmp = CTL_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, CTL_FILE)


def refresh_ctl():
    """Reload the control file only if it changed on disk."""
    global CTL, _ctl_mtime
    try:
        m = os.stat(CTL_FILE).st_mtime
    except FileNotFoundError:
        m = None
    if m != _ctl_mtime:
        CTL = load_ctl()
        _ctl_mtime = m


def map_type():
    r = subprocess.run(["postconf", "-h", "default_database_type"], capture_output=True, text=True)
    return r.stdout.strip() or "hash"


def pause_rule_active(max_age=60):
    """True if Postfix currently has the check_sasl_access pause rule.
    Cached for max_age seconds."""
    now = time.time()
    if _rule["ok"] is None or now - _rule["checked"] >= max_age:
        r = subprocess.run(["postconf", "-h", "smtpd_recipient_restrictions"],
                           capture_output=True, text=True)
        ok = (r.returncode == 0 and "check_sasl_access" in r.stdout
              and os.path.basename(SASL_MAP) in r.stdout)
        if ok != _rule["ok"]:
            txt = ("present" if ok else
                   "MISSING (pauses are NOT enforced; pause accounts fall back to password rotation)")
            print(f"{utc_now()} PAUSE-RULE {txt}", flush=True)
        _rule["ok"], _rule["checked"] = ok, now
    return _rule["ok"]


def utc_now():
    return datetime.datetime.now().astimezone(datetime.timezone.utc).isoformat()


def sync_map(data):
    """Write the Postfix access table from the active pauses and compile it."""
    lines = []
    for email, info in sorted(data["paused"].items()):
        until = datetime.datetime.fromtimestamp(info["until"]).strftime("%Y-%m-%d %H:%M")
        lines.append(f"{email.lower()} {PAUSE_REPLY.format(until=until)}")
    with open(SASL_MAP, "w") as f:
        f.write("# generated by miab-send-guard, do not edit by hand\n")
        f.write("\n".join(lines) + ("\n" if lines else ""))
    r = subprocess.run(["postmap", f"{map_type()}:{SASL_MAP}"], capture_output=True, text=True)
    if r.returncode != 0:
        print(f"postmap failed: {r.stderr.strip()}", flush=True)
    return r.returncode == 0


def pause_account(email, hours, reason="manual"):
    data = load_ctl()
    until = time.time() + hours * 3600
    data["paused"][email.lower()] = {"until": until, "since": utc_now(), "reason": reason}
    save_ctl(data)
    ok = sync_map(data)
    refresh_ctl()
    return ok, until


def resume_account(email):
    """End a pause and start the account's counters from zero."""
    data = load_ctl()
    data["paused"].pop(email.lower(), None)
    data["floor"][email.lower()] = time.time()
    save_ctl(data)
    ok = sync_map(data)
    refresh_ctl()
    return ok


def expire_pauses():
    now = time.time()
    for email, info in list(CTL["paused"].items()):
        if info["until"] <= now:
            resume_account(email)
            print(f"{utc_now()} RESUME {email} (pause expired)", flush=True)


# ---------------------------------------------------------------- state / log

def load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            return json.load(f)
    return {"date": None, "locked": {}}


def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)


def parse_line(line, year):
    m = SASL_RE.match(line)
    if not m:
        return None
    ts_str, user = m.groups()
    try:
        ts = datetime.datetime.strptime(f"{year} {ts_str}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None
    return ts, user


def seed_from_existing_log(path):
    """Read the current log once at startup so counts include today's
    activity already on disk."""
    if not os.path.exists(path):
        return
    now = datetime.datetime.now()
    day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    with open(path, errors="ignore") as f:
        for line in f:
            parsed = parse_line(line, now.year)
            if not parsed:
                continue
            ts, user = parsed
            if day_start <= ts <= now:
                events.append((ts.timestamp(), user))


def trim_events(now_ts):
    cutoff = now_ts - 86400
    while events and events[0][0] < cutoff:
        events.pop(0)


def counted(ts, user):
    """An event counts unless it is older than the account's last resume."""
    return ts >= CTL["floor"].get(user.lower(), 0)


def current_counts(now):
    hour_start = now.replace(minute=0, second=0, microsecond=0).timestamp()
    day_start = now.replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
    hour_counts, day_counts = {}, {}
    for ts, user in events:
        if not counted(ts, user):
            continue
        if ts >= day_start:
            day_counts[user] = day_counts.get(user, 0) + 1
        if ts >= hour_start:
            hour_counts[user] = hour_counts.get(user, 0) + 1
    return hour_counts, day_counts


def burst_count(user, now_ts, seconds):
    cutoff = now_ts - seconds
    return sum(1 for ts, u in events if u == user and ts >= cutoff and counted(ts, u))


def peak_hourly_counts(now):
    """Highest single-hour count per user so far today (ignores resets)."""
    day_start = now.replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
    buckets = {}
    for ts, user in events:
        if ts >= day_start:
            per_user = buckets.setdefault(user, {})
            hr = datetime.datetime.fromtimestamp(ts).hour
            per_user[hr] = per_user.get(hr, 0) + 1
    return {u: max(b.values()) for u, b in buckets.items()}


# ---------------------------------------------------------------- actions

def lock_account(email):
    """Replace the password with a random one nobody knows (via Mail-in-a-Box's
    own CLI). Note: the new password is briefly visible in the process list."""
    new_password = secrets.token_urlsafe(18)
    result = subprocess.run(
        ["python3", CLI, "user", "password", email, new_password],
        cwd=CLI_DIR, capture_output=True, text=True,
    )
    return result.returncode == 0, result.stdout + result.stderr


def fmt_remaining(delta):
    total_minutes = int(delta.total_seconds() // 60)
    h, m = divmod(total_minutes, 60)
    return {"hours": h, "minutes": m, "label": f"{h}h {m}m"}


def check_and_lock(state, today):
    now = datetime.datetime.now()
    hour_counts, day_counts = current_counts(now)

    for user in set(hour_counts) | set(day_counts):
        lim = limits_for(user)
        h = hour_counts.get(user, 0)
        d = day_counts.get(user, 0)
        b = burst_count(user, now.timestamp(), lim["burst_seconds"])

        reasons = []
        if h > lim["hour"]:
            reasons.append(f"hour {h}>{lim['hour']}")
        if d > lim["day"]:
            reasons.append(f"day {d}>{lim['day']}")
        if b > lim["burst"]:
            reasons.append(f"burst {b}>{lim['burst']} in {lim['burst_seconds']}s")
        if not reasons:
            continue

        why = "; ".join(reasons)
        action = lim["action"]
        if action == "pause" and not pause_rule_active():
            action = "rotate"   # Postfix would not enforce a pause: protect the account anyway
            why += "; pause rule missing in Postfix, falling back to password rotation"

        if action == "pause":
            if user.lower() in CTL["paused"]:
                continue
            ok, until = pause_account(user, lim["pause_hours"], reason=why)
            until_s = datetime.datetime.fromtimestamp(until).strftime("%Y-%m-%d %H:%M")
            print(f"{utc_now()} PAUSE {user} ({why}) until {until_s} server time ok={ok}", flush=True)
        elif user not in state["locked"]:
            ok, output = lock_account(user)
            if ok:
                state["locked"][user] = utc_now()
            print(f"{utc_now()} LOCK {user} ({why}) ok={ok} output={output.strip()}", flush=True)
            save_state(state)


def build_snapshot(state):
    now = datetime.datetime.now()
    hour_counts, day_counts = current_counts(now)
    peaks = peak_hourly_counts(now)
    next_hour = now.replace(minute=0, second=0, microsecond=0) + datetime.timedelta(hours=1)
    next_day = now.replace(hour=0, minute=0, second=0, microsecond=0) + datetime.timedelta(days=1)

    accounts = []
    for user in sorted(set(hour_counts) | set(day_counts) | set(CTL["paused"])):
        lim = limits_for(user)
        p = CTL["paused"].get(user.lower())
        accounts.append({
            "account_id": account_id(user),
            "email_masked": mask(user),
            "hour_count": hour_counts.get(user, 0),
            "day_count": day_counts.get(user, 0),
            "peak_hour_count": peaks.get(user, 0),
            "burst_count": burst_count(user, now.timestamp(), lim["burst_seconds"]),
            "hour_limit": lim["hour"],
            "day_limit": lim["day"],
            "burst_limit": lim["burst"],
            "burst_seconds": lim["burst_seconds"],
            "action": lim["action"],
            "locked": user in state["locked"],
            "locked_at": state["locked"].get(user),
            "paused": p is not None,
            "paused_until": (datetime.datetime.fromtimestamp(p["until"]).astimezone(datetime.timezone.utc).isoformat()
                             if p else None),
            "paused_resumes_in": (fmt_remaining(datetime.timedelta(seconds=max(0, p["until"] - now.timestamp())))
                                  if p else None),
        })
    return {
        "generated_at": now.astimezone(datetime.timezone.utc).isoformat(),
        "pause_rule_active": pause_rule_active(),
        "hourly_limit": DEFAULT_LIMITS["hour"],
        "daily_limit": DEFAULT_LIMITS["day"],
        "hour_resets_in": fmt_remaining(next_hour - now),
        "day_resets_in": fmt_remaining(next_day - now),
        "accounts": accounts,
    }


def write_snapshot(state):
    if not JSON_OUT:
        return
    tmp_path = JSON_OUT + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(build_snapshot(state), f, indent=2)
    os.replace(tmp_path, JSON_OUT)  # atomic: no half-written file is ever served


# ---------------------------------------------------------------- commands

def cmd_status():
    data = load_ctl()
    if not data["paused"]:
        print("No accounts are paused.")
    for email, info in data["paused"].items():
        left = max(0, info["until"] - time.time())
        h, m = divmod(int(left // 60), 60)
        until = datetime.datetime.fromtimestamp(info["until"]).strftime("%Y-%m-%d %H:%M")
        print(f"{email}: paused until {until} server time ({h}h {m}m left), reason: {info['reason']}")


def run_command(argv):
    cmd = argv[0]
    if cmd == "init":
        ok = sync_map(load_ctl())
        print("map written and compiled" if ok else "map written but postmap FAILED")
        return 0 if ok else 1
    if cmd == "status":
        cmd_status()
        return 0
    if cmd == "pause" and len(argv) >= 2:
        hours = float(argv[2]) if len(argv) > 2 else DEFAULT_LIMITS["pause_hours"]
        ok, until = pause_account(argv[1], hours, reason="manual")
        print(f"{argv[1]} paused until {datetime.datetime.fromtimestamp(until):%Y-%m-%d %H:%M} server time (map ok={ok})")
        return 0 if ok else 1
    if cmd == "resume" and len(argv) >= 2:
        ok = resume_account(argv[1])
        print(f"{argv[1]} resumed, counters reset (map ok={ok})")
        return 0 if ok else 1
    print(__doc__)
    return 2


# ---------------------------------------------------------------- daemon

def main():
    global SALT
    SALT = get_salt(SALT)
    print(f"limits: default={DEFAULT_LIMITS} overrides={list(OVERRIDES)} mask={MASK.get('mode')}", flush=True)

    state = load_state()
    today = datetime.date.today().isoformat()
    if state.get("date") != today:
        state = {"date": today, "locked": {}}

    if not os.path.exists(LOG_FILE):
        sys.exit(f"mail log not found: {LOG_FILE} (set log_file in config.json)")
    refresh_ctl()
    sync_map(CTL)          # make sure the Postfix map exists and matches
    seed_from_existing_log(LOG_FILE)

    f = open(LOG_FILE, errors="ignore")
    f.seek(0, os.SEEK_END)
    inode = os.fstat(f.fileno()).st_ino
    last_write = 0

    while True:
        # Handle log rotation: file replaced or truncated underneath us.
        try:
            st = os.stat(LOG_FILE)
            if st.st_ino != inode or st.st_size < f.tell():
                f.close()
                f = open(LOG_FILE, errors="ignore")
                inode = os.fstat(f.fileno()).st_ino
        except FileNotFoundError:
            time.sleep(POLL_SECONDS)
            continue

        refresh_ctl()
        line = f.readline()
        if not line:
            time.sleep(POLL_SECONDS)
        else:
            new_today = datetime.date.today().isoformat()
            if new_today != state["date"]:
                state = {"date": new_today, "locked": {}}
            parsed = parse_line(line, datetime.datetime.now().year)
            if parsed:
                ts, user = parsed
                events.append((ts.timestamp(), user))
                trim_events(ts.timestamp())
                check_and_lock(state, state["date"])

        now_ts = time.time()
        if now_ts - last_write >= WRITE_EVERY_SECONDS:
            expire_pauses()
            write_snapshot(state)
            last_write = now_ts


if __name__ == "__main__":
    apply_config(load_config_file())
    if len(sys.argv) > 1:
        SALT = get_salt(SALT)
        sys.exit(run_command(sys.argv[1:]))
    main()
