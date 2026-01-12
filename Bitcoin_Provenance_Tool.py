#!/usr/bin/env python3
"""
===============================================================================
 BITCOIN PROVENANCE TOOL (Stateful Artifact Generator)
===============================================================================
Usage:
  python3 Bitcoin_Provenance_Tool.py              (Menu & Status Browser)
  python3 Bitcoin_Provenance_Tool.py <filename>   (Direct Action)

Features:
  - Tab Autocomplete for filenames.
  - Stateful JSON: Updates status (Pending -> Confirmed).
  - Artifact Recording: Stores filenames of keys, proofs, and targets.
  - Blockchain Data: Saves Block Height & Time to JSON after verification.
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
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# 0. CONFIGURATION
# ---------------------------------------------------------------------------
PROOF_DIR = "bitcoin_proofs"
IDENTITY_FILENAME = "identity.key"  # Default identity

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
    """Generates the standardized JSON filename."""
    base = os.path.basename(target_file)
    return os.path.join(PROOF_DIR, f"{base}.provenance.json")

def show_file_listing():
    print(f"\n{C_CYAN}📁 AVAILABLE FILES IN CURRENT FOLDER:{C_RESET}")
    print("-" * 70)
    try:
        files = [f for f in os.listdir('.') if os.path.isfile(f) and not f.startswith('.')]
        files.sort()
    except OSError:
        files = []

    if not files:
        print("   (No files found)")

    for f in files:
        json_path = get_provenance_filename(f)

        # Determine Status by reading the JSON artifact
        if os.path.exists(json_path):
            try:
                with open(json_path, 'r') as jf:
                    data = json.load(jf)
                    status = data.get("provenance_status", "unknown")

                    if status == "confirmed":
                        icon = "✅"
                        display = f"{C_GREEN}{f} {C_GREY}[Confirmed in Block {data.get('blockchain_data', {}).get('block_height', '?')}]{C_RESET}"
                    elif status == "pending":
                        icon = "⏳"
                        display = f"{C_YELLOW}{f} {C_GREY}[Mining Pending]{C_RESET}"
                    else:
                        icon = "🔒"
                        display = f"{C_GREEN}{f} {C_GREY}[Anchored]{C_RESET}"
            except:
                icon = "❓"
                display = f"{C_RED}{f} [Corrupt JSON]{C_RESET}"
        else:
            icon = "📄"
            display = f"{f}"

        print(f" {icon} {display}")

    print("-" * 70)
    print(f" {C_GREEN}✅ Confirmed{C_RESET} | {C_YELLOW}⏳ Pending{C_RESET} | 📄 New File")

def load_key():
    """Loads the identity key, creating it if necessary."""
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
        print(f"   Saved to: {key_path} (Keep this safe!)")
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

    # 1. Crypto Operations
    sk, key_filename = load_key()
    pk_hex = sk.verify_key.encode(encoder=HexEncoder).decode()
    h256, h512 = get_hash(target_file)

    # Sign Hash + Note
    signature = sk.sign(f"{h512}|{note}".encode()).signature.hex()

    # 2. Define Artifact Filenames
    base_name = os.path.basename(target_file)
    ots_filename = f"{base_name}.ots"
    ots_path = os.path.join(PROOF_DIR, ots_filename)

    # 3. Build State JSON
    manifest = {
        "version": "1.1",
        "provenance_status": "pending",  # Initial state
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

    # 4. Write JSON
    with open(json_path, "w") as f:
        json.dump(manifest, f, indent=2)

    # 5. Stamp
    print(f"⏳ Submitting fingerprint to Bitcoin aggregators...")
    try:
        # We stamp the JSON itself to link the metadata,
        # OR we stamp the file. Stamping the JSON is usually better for provenance metadata.
        # But commonly we stamp the hash. Here we use the standard OTS file flow.
        # We will create a detached timestamp for the FILE hash (h256) indirectly via ots tool on file?
        # Actually, let's stamp the JSON manifest we just created. It contains the file hash.
        # This anchors the *Metadata* + *File Hash* together.

        subprocess.check_call([OTS_EXEC, "stamp", json_path])

        # OTS tool creates json_path.ots. Let's rename it to keep it clean if we want
        # But 'ots stamp' forces .ots extension.
        # Let's align with the manifest "proof_file" entry.
        generated_ots = json_path + ".ots"
        if os.path.exists(generated_ots):
            os.rename(generated_ots, ots_path)

        print(f"\n{C_GREEN}✅ ANCHOR SUBMITTED!{C_RESET}")
        print(f"   Artifacts generated in '{PROOF_DIR}/':")
        print(f"   1. {os.path.basename(json_path)} (Metadata)")
        print(f"   2. {ots_filename} (Cryptographic Proof)")
        print("-" * 60)
        print(f" {C_YELLOW}⏳ NEXT STEP:{C_RESET} Wait 12-24 hours for Bitcoin mining.")
        print(f" Run this tool again later to get your Block Height.")
        print("=" * 60)

    except Exception as e:
        print(f"{C_RED}❌ Error stamping: {e}{C_RESET}")
        # Revert status
        manifest["provenance_status"] = "failed"
        with open(json_path, "w") as f: json.dump(manifest, f, indent=2)

# ---------------------------------------------------------------------------
# 5. WORKFLOW: UPDATE & VERIFY
# ---------------------------------------------------------------------------
def run_existing_verification(json_path):
    print("\n" + "="*60)
    print(f"{C_BOLD} 🔍 EXISTING PROVENANCE FOUND{C_RESET}")
    print("="*60)

    # 1. Load State
    with open(json_path, 'r') as f:
        manifest = json.load(f)

    proof_filename = manifest['artifacts']['proof_file']
    ots_path = os.path.join(PROOF_DIR, proof_filename)

    if not os.path.exists(ots_path):
        print(f"{C_RED}❌ Error: Proof file '{proof_filename}' missing from {PROOF_DIR}.{C_RESET}")
        return

    # 2. Upgrade (Fetch Bitcoin Path)
    print(" 📡 Checking for Bitcoin block updates...")
    upgrade_proc = subprocess.run([OTS_EXEC, "upgrade", ots_path], capture_output=True, text=True)

    # 3. Verify (Read Block Data)
    verify_proc = subprocess.run([OTS_EXEC, "verify", ots_path], capture_output=True, text=True)
    output = verify_proc.stdout

    # 4. Parse Results & Update State
    if "Bitcoin block" in output:
        match_block = re.search(r"Bitcoin block (\d+)", output)
        match_time = re.search(r"attests existence as of (.+)", output)

        block = match_block.group(1) if match_block else "Unknown"
        time_s = match_time.group(1) if match_time else "Unknown"

        # Update JSON State
        manifest["provenance_status"] = "confirmed"
        manifest["last_updated"] = datetime.now(timezone.utc).isoformat()
        manifest["blockchain_data"]["block_height"] = block
        manifest["blockchain_data"]["confirmed_at"] = time_s

        with open(json_path, "w") as f:
            json.dump(manifest, f, indent=2)

        print(f"\n {C_GREEN}✅ CONFIRMED!{C_RESET}")
        print(f"    This file is immutably locked in the Bitcoin Blockchain.")
        print("-" * 40)
        print(f"    🧱 Block Height: {C_CYAN}{block}{C_RESET}")
        print(f"    📅 Confirmed At: {C_CYAN}{time_s}{C_RESET}")
        print("-" * 40)
        print(f"    Artifact updated: {json_path}")

    elif "Pending" in output or "incomplete" in output:
        print(f"\n {C_YELLOW}⏳ STATUS: PENDING MINING{C_RESET}")
        print("    Bitcoin hasn't mined the transaction yet.")
        print("    Please check back in a few hours.")
    else:
        print(f"\n {C_RED}⚠️  STATUS UNKNOWN{C_RESET}")
        print(output)

# ---------------------------------------------------------------------------
# 6. MAIN ENTRY
# ---------------------------------------------------------------------------
def main():
    if len(sys.argv) < 2:
        print(f"{C_BOLD}BITCOIN PROVENANCE TOOL{C_RESET}")
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

    # Determine paths
    json_path = get_provenance_filename(target_file)

    if os.path.exists(json_path):
        run_existing_verification(json_path)
    else:
        run_new_anchor(target_file, json_path)

if __name__ == "__main__":
    main()
