#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Athena V3 Integrity Validator (v6.1 Final)
Hardened for FalconForge production deployment.
"""

import json, hashlib, os, sys, datetime, shutil, traceback, urllib.request, ssl
from pathlib import Path
from jsonschema import validate, ValidationError

BASE_DIR = Path(__file__).resolve().parents[1]
SCHEMAS_DIR = BASE_DIR / "schemas"
ARCHIVE_DIR = BASE_DIR / "archive" / "CAP_LOGS"
CAP_FILE = BASE_DIR / "cap_record.json"
MANIFEST_PATH = SCHEMAS_DIR / "FalconForge_Integrity_Manifest_v3_5.json"
SCHEMA_PATH = SCHEMAS_DIR / "ATHENA_CAP_SCHEMA_v3_5.json"
LOG_RETAIN = 10

CANONICAL = {
    "manifest": "https://raw.githubusercontent.com/falconforge-codex/canonical/FalconForge_Integrity_Manifest_v3_5.json",
    "schema":   "https://raw.githubusercontent.com/falconforge-codex/canonical/ATHENA_CAP_SCHEMA_v3_5.json"
}

# --- Utilities --------------------------------------------------------------
def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""): h.update(chunk)
    return "SHA256:" + h.hexdigest()

def load_json(p: Path):
    with open(p, encoding="utf-8") as f: return json.load(f)

def safe_atomic_write(p: Path, data: str):
    tmp = p.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f: f.write(data)
    os.replace(tmp, p)

def prune_logs():
    logs = sorted(ARCHIVE_DIR.glob("integrity_*.log"), key=os.path.getmtime, reverse=True)
    for old in logs[LOG_RETAIN:]: old.unlink(missing_ok=True)

def redact_tb(tb: str) -> str:
    return "\n".join(line.replace(str(BASE_DIR), "<workspace>") for line in tb.splitlines())

def fetch_secure(url: str) -> str:
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(url, context=ctx, timeout=10) as r:
        return r.read().decode("utf-8")

def log(msg): print(msg, flush=True)

# --- Core -------------------------------------------------------------------
def main():
    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    tstamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    log_path = ARCHIVE_DIR / f"integrity_{tstamp}.log"
    status, verdict = "FAIL", "❌ Integrity Check Failed"

    try:
        log("🔍 Running Athena V3 Integrity Check (v6.1 Final)\n")

        manifest = load_json(MANIFEST_PATH)
        mod = next(m for m in manifest["modules"] if m["name"] == "ATHENA_CAP_SCHEMA_v3_5.json")
        canon_hash = mod["sha256"].split(":")[1]
        local_hash = sha256_file(SCHEMA_PATH).split(":")[1]

        if local_hash != canon_hash:
            log(f"⚠ Schema hash mismatch\n  expected {canon_hash}\n  found   {local_hash}")
            data = fetch_secure(CANONICAL["schema"])
            safe_atomic_write(SCHEMA_PATH, data)
            log("✅ Canonical schema restored and re-hashed.")
            local_hash = sha256_file(SCHEMA_PATH).split(":")[1]
            if local_hash != canon_hash:
                raise ValueError("Post-fetch hash still mismatch.")

        schema = load_json(SCHEMA_PATH)
        cap = load_json(CAP_FILE)
        validate(instance=cap, schema=schema)

        verdict, status = "✅ Integrity Verified — Hashes Match + CAP Valid.", "PASS"
        log(verdict)

    except (FileNotFoundError, KeyError) as e:
        verdict = f"❌ Missing required file or manifest key → {e}"
        log(verdict)
    except ValidationError as e:
        verdict = f"❌ CAP Validation Error: {e.message}"
        log(verdict)
    except Exception as e:
        verdict = f"❌ Unhandled Error:\n{redact_tb(traceback.format_exc())}"
        log(verdict)
    finally:
        record = {
            "runtime": datetime.datetime.utcnow().isoformat() + "Z",
            "manifest_version": manifest.get("version", "unknown") if 'manifest' in locals() else "unknown",
            "schema_hash": local_hash if 'local_hash' in locals() else "N/A",
            "verdict": verdict,
            "status": status
        }
        safe_atomic_write(log_path, json.dumps(record, indent=2, ensure_ascii=False))
        prune_logs()
        log(f"\n🪶 Audit log archived → {log_path}")
        sys.exit(0 if status == "PASS" else 1)

if __name__ == "__main__":
    main()
