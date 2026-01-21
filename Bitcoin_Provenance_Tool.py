#!/usr/bin/env python3
"""
===============================================================================
 BITCOIN PROVENANCE TOOL v1.8 (Fix Block Height Upgrade)
 by Anthro Entertainment LLC (Anthro Teacher) 1/17/2026
 MIT Licensed
===============================================================================
Usage:
  python3 Bitcoin_Provenance_Tool.py <filename>
===============================================================================
"""

import os
import sys
import json
import hashlib
import subprocess
import shutil
import re
import glob
import readline
import time
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# 0. CONFIGURATION
# ---------------------------------------------------------------------------
PROOF_DIR = "bitcoin_proofs"
IDENTITY_FILENAME = "identity.key"
LEDGER_FILENAME = "master_ledger.json"

# Colors
C_RESET  = "\033[0m"
C_CYAN   = "\033[1;36m"
C_GREEN  = "\033[1;32m"
C_YELLOW = "\033[1;33m"
C_RED    = "\033[1;31m"
C_BOLD   = "\033[1m"
C_GREY   = "\033[90m"

# ---------------------------------------------------------------------------
# 1. SETUP: TAB AUTOCOMPLETE
# ---------------------------------------------------------------------------
def path_completer(text, state):
    if '~' in text: text = os.path.expanduser(text)
    return [x for x in glob.glob(text + '*')][state]

readline.set_completer_delims(' \t\n;')
readline.parse_and_bind("tab: complete")
readline.set_completer(path_completer)

# ---------------------------------------------------------------------------
# 2. DEPENDENCY CHECKS
# ---------------------------------------------------------------------------
def check_requirements():
    missing = []
    try:
        import nacl.signing
    except ImportError:
        missing.append("pynacl")

    ots_path = shutil.which("ots")
    if not ots_path:
        user_bin = os.path.expanduser("~/.local/bin/ots")
        if os.path.exists(user_bin):
            ots_path = user_bin
        else:
            missing.append("opentimestamps-client")

    if missing:
        print(f"{C_RED}❌ MISSING REQUIREMENTS{C_RESET}")
        print(f"   pip install {' '.join(missing)} --user --break-system-packages")
        sys.exit(1)
    return ots_path

OTS_EXEC = check_requirements()
from nacl.signing import SigningKey
from nacl.encoding import HexEncoder

# ---------------------------------------------------------------------------
# 3. HELPER FUNCTIONS
# ---------------------------------------------------------------------------
def get_provenance_filename(target_file):
    base = os.path.basename(target_file)
    return os.path.join(PROOF_DIR, f"{base}.provenance.json")

def backup_proof(source_ots_path):
    """Create a timestamped backup of the proof before upgrade."""
    if not os.path.exists(source_ots_path):
        return None

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    backup_path = f"{source_ots_path}.bak-{timestamp}"

    # Only backup if we don't already have one for this exact name (avoid duplicates)
    if not os.path.exists(backup_path):
        shutil.copy2(source_ots_path, backup_path)
        print(f"   📦 Backup created: {os.path.basename(backup_path)}")
    else:
        print(f"   📦 Backup already exists for this timestamp.")

    return backup_path

def update_master_ledger(record_entry):
    ledger_path = os.path.join(PROOF_DIR, LEDGER_FILENAME)
    ledger_data = {"records": {}}

    if os.path.exists(ledger_path):
        try:
            with open(ledger_path, 'r') as f:
                ledger_data = json.load(f)
        except json.JSONDecodeError:
            pass

    fname = record_entry['target_file']['filename']
    ledger_data['records'][fname] = {
        "status": record_entry['provenance_status'],
        "last_updated": record_entry['last_updated'],
        "block_height": record_entry['blockchain_data']['block_height'],
        "note": record_entry.get('user_note', ''),
        "sha256": record_entry['target_file']['sha256']
    }

    with open(ledger_path, 'w') as f:
        json.dump(ledger_data, f, indent=2)

    print(f"   📘 Ledger updated: {ledger_path}")

def show_file_listing():
    print(f"\n{C_CYAN}📁 AVAILABLE FILES:{C_RESET}")
    print("-" * 70)

    ledger_path = os.path.join(PROOF_DIR, LEDGER_FILENAME)
    ledger_records = {}
    if os.path.exists(ledger_path):
        try:
            with open(ledger_path, 'r') as f:
                ledger_records = json.load(f).get("records", {})
        except: pass

    try:
        files = [f for f in os.listdir('.') if os.path.isfile(f) and not f.startswith('.')]
        files.sort()
    except OSError:
        files = []

    if not files:
        print("   (No files found)")

    for f in files:
        if f in ledger_records:
            rec = ledger_records[f]
            status = rec.get('status')
            if status == "confirmed":
                icon = "✅"
                display = f"{C_GREEN}{f} {C_GREY}[Block {rec.get('block_height')}]{C_RESET}"
            else:
                icon = "⏳"
                display = f"{C_YELLOW}{f} {C_GREY}[Pending]{C_RESET}"
        else:
            json_path = get_provenance_filename(f)
            if os.path.exists(json_path):
                 icon = "⏳"
                 display = f"{C_YELLOW}{f} {C_GREY}[Anchored/Unindexed]{C_RESET}"
            else:
                icon = "📄"
                display = f"{f}"

        print(f" {icon} {display}")

    print("-" * 70)

def load_key():
    if not os.path.exists(PROOF_DIR): os.makedirs(PROOF_DIR)

    key_path = os.path.join(PROOF_DIR, IDENTITY_FILENAME)

    if os.path.exists(key_path):
        with open(key_path, "r") as f:
            return SigningKey(f.read().strip(), encoder=HexEncoder), IDENTITY_FILENAME
    else:
        print(f"\n{C_YELLOW}✨ Generating NEW Identity Key...{C_RESET}")
        sk = SigningKey.generate()
        with open(key_path, "w") as f:
            f.write(sk.encode(encoder=HexEncoder).decode())
        print(f"   Saved to: {key_path}")
        return sk, IDENTITY_FILENAME

def get_hash(filepath):
    print(f"{C_CYAN}⚙️  Hashing {os.path.basename(filepath)}...{C_RESET}")
    sha256, sha512 = hashlib.sha256(), hashlib.sha512()
    total = os.path.getsize(filepath)
    processed = 0
    with open(filepath, "rb") as f:
        while chunk := f.read(16*1024*1024):
            sha256.update(chunk)
            sha512.update(chunk)
            processed += len(chunk)
            if total > 0: print(f"   {int((processed/total)*100)}%", end="\r")
    print("   ✅ Hashing Complete.\n")
    return sha256.hexdigest(), sha512.hexdigest()

# ---------------------------------------------------------------------------
# 4. WORKFLOW: NEW ANCHOR
# ---------------------------------------------------------------------------
def run_new_anchor(target_file, json_path):
    print("\n" + "="*60)
    print(f"{C_BOLD} 🆕 NEW FILE DETECTED{C_RESET}")
    print("="*60)

    note = input(f" Enter a Note for the Blockchain (e.g. 'v1.0') [Enter to skip]: ").strip()

    sk, key_filename = load_key()
    pk_hex = sk.verify_key.encode(encoder=HexEncoder).decode()
    h256, h512 = get_hash(target_file)

    signature = sk.sign(f"{h512}|{note}".encode()).signature.hex()

    base_name = os.path.basename(target_file)
    ots_filename = f"{base_name}.provenance.json.ots"
    ots_path = os.path.join(PROOF_DIR, ots_filename)

    manifest = {
        "version": "1.1",
        "provenance_status": "pending",
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "target_file": {
            "filename": base_name,
            "size_bytes": os.path.getsize(target_file),
            "sha256": h256,
            "sha512": h512
        },
        "artifacts": {
            "proof_file": ots_filename,
            "key_file": key_filename,
            "json_file": os.path.basename(json_path)
        },
        "identity": {
            "public_key": pk_hex,
            "signature": signature,
            "signed_payload": "sha512|note"
        },
        "blockchain_data": {
            "block_height": None,
            "confirmed_at": None
        },
        "user_note": note
    }

    with open(json_path, "w") as f:
        json.dump(manifest, f, indent=2)

    update_master_ledger(manifest)

    print(f"⏳ Submitting fingerprint to Bitcoin aggregators...")
    try:
        subprocess.check_call([OTS_EXEC, "stamp", json_path])
        generated_ots = json_path + ".ots"
        if os.path.exists(generated_ots):
            shutil.move(generated_ots, ots_path)

        print(f"\n{C_GREEN}✅ ANCHOR SUBMITTED!{C_RESET}")
        print(f"   Artifacts in '{PROOF_DIR}/':")
        print(f"   1. {os.path.basename(json_path)} (Record)")
        print(f"   2. {ots_filename} (Proof)")
        print(f"   3. {LEDGER_FILENAME} (Ledger)")
        print("-" * 60)
        print(f" {C_YELLOW}⏳ NEXT STEP:{C_RESET} Re-run the tool—it will auto-upgrade & backup each time.")
        print("    Bitcoin confirmations can take hours to days—totally normal for free calendars!")
        print("=" * 60)

    except Exception as e:
        print(f"{C_RED}❌ Error stamping: {e}{C_RESET}")

# ---------------------------------------------------------------------------
# 5. WORKFLOW: AUTO-UPGRADE + BACKUP + VERIFY
# ---------------------------------------------------------------------------
def run_existing_verification(target_file, json_path):
    print("\n" + "="*60)
    print(f"{C_BOLD} 🔍 EXISTING PROVENANCE FOUND{C_RESET}")
    print("="*60)

    with open(json_path, 'r') as f:
        manifest = json.load(f)

    proof_filename = manifest['artifacts']['proof_file']
    source_ots_path = os.path.join(PROOF_DIR, proof_filename)

    if not os.path.exists(source_ots_path):
        print(f"{C_RED}❌ Error: Proof file '{source_ots_path}' missing.{C_RESET}")
        return

    # BACKUP BEFORE UPGRADE
    print(f"{C_CYAN}🔄 Preparing upgrade (with backup)...{C_RESET}")
    backup_proof(source_ots_path)

    # AUTO-UPGRADE with retry
    upgraded = False
    for attempt in range(1, 3):
        upgrade_proc = subprocess.run([OTS_EXEC, "upgrade", source_ots_path], capture_output=True, text=True)
        if upgrade_proc.returncode == 0:
            upgraded = True
            print(f"   Upgrade successful (attempt {attempt}).")
            break
        else:
            print(f"   Upgrade attempt {attempt} issue: {upgrade_proc.stderr.strip()[:100]}...")
            if attempt < 2:
                time.sleep(3)

    if not upgraded:
        print(f"{C_YELLOW}⚠️ Upgrade didn't complete cleanly—checking current status anyway...{C_RESET}")

    # Get info
    print(" 📡 Retrieving current status...")
    info_proc = subprocess.run([OTS_EXEC, "info", source_ots_path], capture_output=True, text=True)
    output = info_proc.stdout + info_proc.stderr

    # Integrity checks
    current_h256, _ = get_hash(target_file)
    if current_h256 != manifest['target_file']['sha256']:
        print(f"{C_RED}⚠️ WARNING: Target file changed! Hash mismatch.{C_RESET}")
        print(f"    Original: {manifest['target_file']['sha256'][:16]}...")
        print(f"    Current:  {current_h256[:16]}...")
    else:
        print(f"{C_GREEN}✅ Target file hash matches.{C_RESET}")

    committed_match = re.search(r"File sha256 hash: (\w+)", output)
    if committed_match:
        committed = committed_match.group(1)
        json_h256, _ = get_hash(json_path)
        if json_h256 != committed:
            print(f"{C_RED}⚠️ WARNING: JSON manifest changed! Mismatch with proof.{C_RESET}")
        else:
            print(f"{C_GREEN}✅ JSON matches proof.{C_RESET}")

    # Parse status (FIXED: confirmed beats pending)
    heights = []
    heights += [int(x) for x in re.findall(r"BitcoinBlockHeaderAttestation\((\d+)\)", output)]
    heights += [int(x) for x in re.findall(r"Bitcoin block\s+(\d+)", output)]
    heights = sorted(set(heights))

    if heights:
        block = str(heights[0])  # earliest confirmed block height

        # Optional: sometimes included, sometimes not
        match_time = re.search(r"attests existence as of (.+)", output)
        time_s = match_time.group(1).strip() if match_time else "Unknown"

        manifest["provenance_status"] = "confirmed"
        manifest["last_updated"] = datetime.now(timezone.utc).isoformat()
        manifest["blockchain_data"]["block_height"] = block
        manifest["blockchain_data"]["confirmed_at"] = time_s

        with open(json_path, "w") as f:
            json.dump(manifest, f, indent=2)

        update_master_ledger(manifest)

        print(f"\n {C_GREEN}✅ CONFIRMED IN BITCOIN (Earliest Block {block})!{C_RESET}")
        if len(heights) > 1:
            print(f"    Also confirmed in blocks: {', '.join(str(h) for h in heights)}")

        # --- DONATION / OFFICIAL LINK ---
        print("-" * 60)
        print(f" {C_CYAN}💰 OFFICIAL DONATION LINK VERIFIED:{C_RESET}")
        print(f"    https://ko-fi.com/anthroteacher")
        print("-" * 60)
        # --------------------------------

        if time_s != "Unknown":
            print(f"    Timestamp: {time_s}")

    elif "Pending confirmation" in output or "pendingattestation" in output.lower() or "pending" in output.lower():
        print(f"\n {C_YELLOW}⏳ STATUS: STILL PENDING{C_RESET}")
        print("    Some calendars are still pending (normal).")
        print("    Re-run anytime—the tool auto-upgrades & backs up each time!")
        print(f"    Manual check: ots info {source_ots_path}")

    else:
        print(f"\n {C_RED}⚠️ STATUS UNKNOWN{C_RESET}")
        print(f"{C_GREY}--- RAW OUTPUT ---{C_RESET}")
        print(output.strip())
        print(f"{C_GREY}------------------{C_RESET}")

    # Clean ots temp backups if any
    if os.path.exists(source_ots_path + ".bak"):
        os.remove(source_ots_path + ".bak")

# ---------------------------------------------------------------------------
# 6. MAIN ENTRY
# ---------------------------------------------------------------------------
def main():
    if len(sys.argv) < 2:
        print(f"{C_BOLD}BITCOIN PROVENANCE TOOL v1.8{C_RESET}")
        show_file_listing()
        try:
            user_input = input(f"\n{C_YELLOW}Enter filename > {C_RESET}").strip().strip("'")
        except KeyboardInterrupt:
            print("\nExiting."); sys.exit(0)
        if not user_input: sys.exit(0)
        target_file = user_input
    else:
        target_file = sys.argv[1]

    if not os.path.exists(target_file):
        print(f"{C_RED}❌ Error: File '{target_file}' not found.{C_RESET}")
        sys.exit(1)

    json_path = get_provenance_filename(target_file)

    if os.path.exists(json_path):
        run_existing_verification(target_file, json_path)
    else:
        run_new_anchor(target_file, json_path)

if __name__ == "__main__":
    main()
