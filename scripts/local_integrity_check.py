#!/usr/bin/env python3
import json, hashlib, sys, os, requests
from datetime import datetime
from pathlib import Path
from jsonschema import validate, ValidationError
from colorama import Fore, Style, init

init(autoreset=True)

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = ROOT / "schemas/ATHENA_CAP_SCHEMA_v3_5.json"
MANIFEST = ROOT / "schemas/FalconForge_Integrity_Manifest_v3_5.json"
CAP = ROOT / "cap_record.json"
CONFIG = ROOT / "config/bridge_config.json"
LOGDIR = ROOT / "archive/CAP_LOGS"
LOGDIR.mkdir(parents=True, exist_ok=True)

def log(msg):
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    with open(LOGDIR / f"integrity_{timestamp}.log", "a", encoding="utf-8") as f:
        f.write(msg + "\n")
    print(msg)

def sha256sum(path: Path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def relay_to_bridge(cap_json):
    try:
        with open(CONFIG, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        url, token = cfg["bridge_url"], cfg["auth_token"]
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        r = requests.post(f"{url}/cap", headers=headers, json=cap_json, timeout=15)
        if r.ok:
            log(Fore.CYAN + f"Bridge relay success: {r.status_code}")
        else:
            log(Fore.RED + f"Bridge relay failed: {r.status_code} {r.text}")
    except Exception as e:
        log(Fore.YELLOW + f"Bridge relay error: {e}")

def main():
    try:
        manifest = json.load(open(MANIFEST))
        expected = [m["sha256"].split(":")[1] for m in manifest["modules"]
                    if m["name"] == "ATHENA_CAP_SCHEMA_v3_5.json"][0]
        actual = sha256sum(SCHEMA)
        if actual != expected:
            log(Fore.RED + "❌ Schema integrity mismatch.")
            sys.exit(1)
        log(Fore.GREEN + "✅ Schema integrity verified.")
    except Exception as e:
        log(Fore.RED + f"Manifest load error: {e}")
        sys.exit(1)

    try:
        schema = json.load(open(SCHEMA))
        cap = json.load(open(CAP))
        validate(instance=cap, schema=schema)
        log(Fore.GREEN + "✅ CAP payload structure valid.")
        relay_to_bridge(cap)
    except ValidationError as e:
        log(Fore.RED + f"❌ CAP validation failed: {e.message}")
        sys.exit(1)
    except Exception as e:
        log(Fore.RED + f"Unexpected error: {e}")
        sys.exit(1)

    logs = sorted(LOGDIR.glob("integrity_*.log"), key=os.path.getmtime, reverse=True)
    for old in logs[10:]:
        old.unlink(missing_ok=True)
    log(Fore.CYAN + "🪶 Log archival complete.")

if __name__ == "__main__":
    main()
