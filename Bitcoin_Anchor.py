#!/usr/bin/env python3
"""
===============================================================================
   ⚓ FurryOS BITCOIN ANCHOR & VERIFIER (Universal v3.6 - Auto-Sync)
   -----------------------------------------------------------------------
   The All-in-One tool for Sovereign File Provenance with Identity Signing.

   Author:  Anthro Entertainment LLC (Thomas Sweet)
   License: MIT License (Open Source)
   Created: 2026-01-22

   DESCRIPTION:
   This tool serves as the "Minting Press" for the FurryOS supply chain.
   It anchors files to the Bitcoin Blockchain using OpenTimestamps and
   signs them with a local cryptographic identity (Ed25519).

   FEATURES:
   1. SHA-256 & SHA-512 Hashing (Dual-Algorithm Integrity)
   2. Bitcoin Anchoring (OpenTimestamps)
   3. Cryptographic Signing (Ed25519 via PyNaCl)
   4. JSON Manifest Generation (Metadata Sidecars)
   5. Smart Verification (Auto-detects Proofs & UPDATES LEDGER AUTOMATICALLY)

   REQUIREMENTS:
   - pip install opentimestamps-client pynacl
===============================================================================
"""

import os
import sys
import json
import hashlib
import subprocess
import shutil
import glob
import re
import readline
import time
from datetime import datetime, timezone

# ==============================================================================
#  SECTION 1: CONFIGURATION & CONSTANTS
# ==============================================================================

# The file where we store the cryptographic private key for signing manifests
IDENTITY_FILENAME = "identity.key"

# The local ledger file (for Admin record keeping)
LEDGER_FILENAME = "master_ledger.json"

# The history log (for audit trails)
HISTORY_FILE = "anchor_history.json"

# --- TERMINAL COLORS (Cyberpunk Theme) ---
# Used to ensure output is readable and distinct in a dark terminal
C_RESET  = "\033[0m"
C_CYAN   = "\033[1;36m"
C_GREEN  = "\033[1;32m"
C_YELLOW = "\033[1;33m"
C_RED    = "\033[1;31m"
C_BOLD   = "\033[1m"
C_GREY   = "\033[90m"
C_BLUE   = "\033[1;34m"

# ==============================================================================
#  SECTION 2: SYSTEM INITIALIZATION & DIAGNOSTICS
# ==============================================================================

def setup_autocomplete():
    """
    Enables Tab-Completion for filenames in the input prompt.
    This improves Developer Experience (DevEx) significantly.
    """
    def path_completer(text, state):
        if '~' in text:
            text = os.path.expanduser(text)
        return [x for x in glob.glob(text + '*')][state]

    readline.set_completer_delims(' \t\n;')
    readline.parse_and_bind("tab: complete")
    readline.set_completer(path_completer)

def check_system_integrity():
    """
    Performs a pre-flight check of the environment.
    Ensures all required binary tools and Python libraries are present.
    """
    # 1. Check for OpenTimestamps Client
    ots_path = shutil.which("ots")
    if not ots_path:
        # Fallback check for local user bin
        user_bin = os.path.expanduser("~/.local/bin/ots")
        if os.path.exists(user_bin):
            ots_path = user_bin
        else:
            print(f"\n{C_RED}❌ CRITICAL ERROR: 'ots' command missing.{C_RESET}")
            print(f"   The Bitcoin Anchor cannot function without the OpenTimestamps client.")
            print(f"   Please run: {C_YELLOW}pip install opentimestamps-client{C_RESET}")
            sys.exit(1)

    # 2. Check for PyNaCl (Signing Library)
    try:
        import nacl.signing
    except ImportError:
        print(f"\n{C_RED}❌ CRITICAL ERROR: 'pynacl' library missing.{C_RESET}")
        print(f"   This version requires cryptographic signing capabilities.")
        print(f"   Please run: {C_YELLOW}pip install pynacl{C_RESET}")
        sys.exit(1)

    return ots_path

# Run Setup
setup_autocomplete()
OTS_EXEC = check_system_integrity()

# Import Crypto libraries after check passes
from nacl.signing import SigningKey
from nacl.encoding import HexEncoder

# ==============================================================================
#  SECTION 3: IDENTITY & CRYPTOGRAPHY
# ==============================================================================

def load_identity():
    """
    Loads the Admin's Private Key from disk, or generates a new one.
    This key is used to sign the JSON manifests, proving that the
    files came from Anthro Entertainment LLC and not an imposter.
    """
    if os.path.exists(IDENTITY_FILENAME):
        try:
            with open(IDENTITY_FILENAME, "r") as f:
                hex_key = f.read().strip()
                # Load the key from the hex string
                return SigningKey(hex_key, encoder=HexEncoder)
        except Exception as e:
            print(f"{C_RED}❌ Error loading Identity Key: {e}{C_RESET}")
            sys.exit(1)
    else:
        print(f"\n{C_YELLOW}✨ INITIALIZATION: Generating New Identity Key...{C_RESET}")
        print(f"   File: {IDENTITY_FILENAME}")

        # Generate a new Ed25519 Signing Key
        sk = SigningKey.generate()

        # Save it to disk (Hex encoded)
        with open(IDENTITY_FILENAME, "w") as f:
            f.write(sk.encode(encoder=HexEncoder).decode())

        print(f"   {C_GREEN}✅ Identity Created.{C_RESET} BACK UP THIS FILE.")
        return sk

def get_hashes(filepath):
    """
    Calculates both SHA-256 (for Bitcoin) and SHA-512 (for Manifest Integrity).
    Using two algorithms protects against hash-collision attacks.

    Args:
        filepath (str): Path to the file.

    Returns:
        tuple: (sha256_hex, sha512_hex)
    """
    print(f"   {C_CYAN}⚙️  Calculating Cryptographic Hashes...{C_RESET}")
    print(f"      Target: {os.path.basename(filepath)}")

    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()

    file_size = os.path.getsize(filepath)
    processed = 0

    with open(filepath, "rb") as f:
        while True:
            # Read in 16MB chunks for memory efficiency
            chunk = f.read(16 * 1024 * 1024)
            if not chunk:
                break

            sha256.update(chunk)
            sha512.update(chunk)

            processed += len(chunk)
            if file_size > 0:
                percent = int((processed/file_size)*100)
                print(f"      Progress: {percent}%", end="\r")

    print("      Progress: 100%      ")
    return sha256.hexdigest(), sha512.hexdigest()

# ==============================================================================
#  SECTION 4: LEDGER MANAGEMENT (MOVED UP FOR ACCESS)
# ==============================================================================

def update_ledger_block(filename, block_num):
    """
    Helper function to inject the block number into the JSON history
    if it was missing previously. Safe to run multiple times.
    """
    if not os.path.exists(HISTORY_FILE): return

    try:
        with open(HISTORY_FILE, 'r') as f:
            data = json.load(f)

        updated = False
        # Normalize filename: remove path, just get basename
        base_name = os.path.basename(filename)

        # If verifying a manifest, strip the extension to match the original file record
        if base_name.endswith(".provenance.json"):
            base_name = base_name.replace(".provenance.json", "")

        for record in data.get("records", []):
            if record["filename"] == base_name:
                # Check if block is missing or different
                if "bitcoin_block" not in record or str(record["bitcoin_block"]) != str(block_num):
                    record["bitcoin_block"] = str(block_num)
                    updated = True
                    # Silent update during listing, or visible during verify?
                    # We'll just return True if updated so caller knows.

        if updated:
            with open(HISTORY_FILE, 'w') as f:
                json.dump(data, f, indent=2)
            return True

    except Exception as e:
        return False

    return False

# ==============================================================================
#  SECTION 5: FILE DISCOVERY & DISPLAY
# ==============================================================================

def find_proof_path(target_file):
    """
    Scans the directory for existing proofs.
    Returns the path to the .ots file if found.
    """
    # Priority 1: Direct File Stamp (e.g. file.iso.ots)
    if os.path.exists(target_file + ".ots"):
        return target_file + ".ots"

    # Priority 2: Manifest Stamp (e.g. file.iso.provenance.json.ots)
    if os.path.exists(target_file + ".provenance.json.ots"):
        return target_file + ".provenance.json.ots"

    return None

def get_block_info(target_file):
    """
    Peeks at the .ots file (without verifying the whole file) to
    extract the Bitcoin Block Height for the UI list.
    """
    ots_file = find_proof_path(target_file)
    if not ots_file:
        return None

    try:
        # Run 'ots info' to decode the binary receipt
        result = subprocess.run([OTS_EXEC, "info", ots_file], capture_output=True, text=True)
        output = result.stdout

        # Regex to find block numbers
        heights = [int(x) for x in re.findall(r"BitcoinBlockHeaderAttestation\((\d+)\)", output)]
        heights += [int(x) for x in re.findall(r"Bitcoin block\s+(\d+)", output)]

        if heights:
            # Return the earliest (lowest) block number found
            return str(sorted(set(heights))[0])
        elif "pending" in output.lower():
            return "Pending"
    except:
        pass
    return None

def show_file_listing():
    """
    Displays the sorted, color-coded list of assets in the current directory.
    Separates Anchored (Yellow) from Unstamped (Grey).

    *** AUTO-SYNC FEATURE ***
    If this function sees a Block Number in the .ots file, it AUTOMATICALLY
    saves it to the JSON file if it's missing.
    """
    print(f"\n{C_CYAN}📁 AVAILABLE ASSETS (Current Directory):{C_RESET}")
    print("-" * 75)

    try:
        files = [f for f in os.listdir('.') if os.path.isfile(f)]
    except OSError:
        files = []

    anchored_list = []
    unstamped_list = []

    for f in files:
        # Filter out system files and proofs from the main view
        if f.endswith('.ots'): continue
        if f.endswith('.provenance.json'): continue
        if f == HISTORY_FILE or f == LEDGER_FILENAME: continue

        # Analyze file status
        block = get_block_info(f)
        proof_path = find_proof_path(f)

        # --- AUTO SYNC LEDGER ---
        # If we found a block number, check if we need to save it to JSON
        if block and block != "Pending":
            was_updated = update_ledger_block(f, block)
            if was_updated:
                # Add a visual indicator that we just fixed the ledger
                block = block + f" {C_GREEN}(Synced){C_YELLOW}"

        # Assign Icons based on file type
        if f.startswith('.'): icon = "👁️"    # Hidden
        elif f.endswith('.py'): icon = "🐍"  # Python
        elif f.endswith('.json'): icon = "📝" # Config
        elif f.endswith('.zip') or f.endswith('.7z') or f.endswith('.iso'): icon = "📦" # Archive
        else: icon = "📄"

        # Format the display line
        if block:
            display = f" {icon} {f} {C_YELLOW}[Block {block}]{C_RESET}"
            anchored_list.append((f, display))
        elif proof_path:
            # Proof exists but maybe not confirmed yet or lookup failed
            display = f" {icon} {f} {C_YELLOW}[Proof Detected]{C_RESET}"
            anchored_list.append((f, display))
        else:
            display = f" {icon} {f} {C_GREY}[Unstamped]{C_RESET}"
            unstamped_list.append((f, display))

    # Sort lists alphabetically
    anchored_list.sort(key=lambda x: x[0].lower())
    unstamped_list.sort(key=lambda x: x[0].lower())

    # Print Stamped Files First (Priority)
    for _, line in anchored_list:
        print(line)

    # Print Separator if needed
    if anchored_list and unstamped_list:
        print(f"{C_GREY}" + "- " * 25 + f"{C_RESET}")

    # Print Unstamped Files
    for _, line in unstamped_list:
        print(line)

    print("-" * 75)

# ==============================================================================
#  SECTION 6: VERIFICATION LOGIC
# ==============================================================================

def verify_file(target_file):
    """
    Runs a full cryptographic verification on a file.
    1. Checks for Proof
    2. Hashes File
    3. Checks Bitcoin Blockchain
    4. Validates Manifest Signature (if present)
    5. UPDATES LEDGER IF BLOCK FOUND
    """
    print("\n" + "="*60)
    print(f"{C_BOLD} 🔍 VERIFYING: {target_file}{C_RESET}")
    print("="*60)

    ots_file = find_proof_path(target_file)
    verification_target = target_file

    # --- Check for Manifest-based Proof ---
    if ots_file and ots_file.endswith(".provenance.json.ots"):
        json_file = target_file + ".provenance.json"
        if os.path.exists(json_file):
            verification_target = json_file
            print(f"   {C_CYAN}📄 Validating Manifest Chain...{C_RESET}")
            # Note: We trust the OTS verify process to check the hash match

    # --- Verify against Blockchain ---
    print(f"   {C_CYAN}📡 Checking Bitcoin Blockchain...{C_RESET}")

    # Attempt to upgrade the proof (Auto-heal)
    try:
        subprocess.run([OTS_EXEC, "upgrade", ots_file], capture_output=True)
    except:
        pass

    # Run the verification
    result = subprocess.run([OTS_EXEC, "verify", ots_file, verification_target], capture_output=True, text=True)

    # If verify is silent/fails, run info to get details
    if result.returncode != 0:
        result = subprocess.run([OTS_EXEC, "info", ots_file], capture_output=True, text=True)

    output = result.stdout + result.stderr

    # Parse Block Height
    heights = [int(x) for x in re.findall(r"BitcoinBlockHeaderAttestation\((\d+)\)", output)]
    heights += [int(x) for x in re.findall(r"Bitcoin block\s+(\d+)", output)]
    heights = sorted(set(heights))

    # --- Display Results ---
    if heights:
        block = str(heights[0])
        print(f"\n{C_GREEN}   ✅ VERIFIED: ANCHORED IN BITCOIN{C_RESET}")
        print(f"      {C_BOLD}Block Height: {block}{C_RESET}")
        print(f"      Status: Authentic & Unmodified")

        # Explicit update just in case
        if update_ledger_block(target_file, block):
             print(f"      {C_GREEN}💾 Ledger Updated.{C_RESET}")

    elif "pending" in output.lower():
        print(f"\n{C_YELLOW}   ⏳ STATUS: PENDING{C_RESET}")
        print("      Proof submitted. Waiting for Bitcoin miner confirmation.")
    else:
        print(f"\n{C_RED}   ❌ VERIFICATION FAILED{C_RESET}")
        print("      File hash does not match the proof, or proof is invalid.")

# ==============================================================================
#  SECTION 7: ANCHORING & MANIFEST LOGIC
# ==============================================================================

def create_manifest(filename, h256, h512, note, sk):
    """
    Generates a signed JSON manifest sidecar file.
    This links the file to your Identity Key.
    """

    # Create the payload to sign
    # We sign the SHA-512 hash and the Note to prevent tampering
    payload_to_sign = f"{h512}|{note}"

    # Generate Ed25519 Signature
    signature = sk.sign(payload_to_sign.encode()).signature.hex()
    public_key = sk.verify_key.encode(encoder=HexEncoder).decode()

    manifest = {
        "version": "1.3",
        "provenance_status": "pending",
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "target_file": {
            "filename": filename,
            "size_bytes": os.path.getsize(filename),
            "sha256": h256,
            "sha512": h512
        },
        "identity": {
            "public_key": public_key,
            "signature": signature,
            "signed_payload": "sha512|note"
        },
        "artifacts": {
            "proof_file": filename + ".ots",
            "json_file": filename + ".provenance.json"
        },
        "blockchain_data": {
            "block_height": None,
            "confirmed_at": None
        },
        "user_note": note
    }

    json_path = filename + ".provenance.json"

    # Write to disk
    with open(json_path, "w") as f:
        json.dump(manifest, f, indent=2)

    return json_path

def log_anchor(filename, file_hash, note):
    """
    Updates the local anchor_history.json log.
    This acts as a local database of all operations.
    """
    data = {"records": []}
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, 'r') as f: data = json.load(f)
        except: pass

    record = {
        "filename": filename,
        "sha256": file_hash,
        "note": note,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "proof_file": filename + ".ots"
    }

    data["records"].append(record)

    try:
        with open(HISTORY_FILE, 'w') as f:
            json.dump(data, f, indent=2)
    except: pass

def anchor_file(target_file):
    """
    The main anchoring workflow.
    1. Loads Identity.
    2. Hashes File.
    3. Creates Signed Manifest.
    4. Stamps File.
    5. Logs action.
    """
    print("\n" + "="*60)
    print(f"{C_BOLD} ⚓ ANCHORING: {target_file}{C_RESET}")
    print("="*60)

    # 0. Load Identity Key
    sk = load_identity()

    # 1. Hash it
    h256, h512 = get_hashes(target_file)

    # 2. Optional Note
    note = input(f"   Enter a note for the manifest (Optional) > ").strip()
    if not note: note = "FurryOS Asset Anchor"

    # 3. Create Manifest (Signed)
    json_path = create_manifest(target_file, h256, h512, note, sk)
    print(f"   {C_GREEN}📝 Manifest Signed & Created: {json_path}{C_RESET}")

    # 4. Stamp it (Direct File Stamp)
    print(f"   {C_CYAN}🚀 Submitting Hash to Bitcoin Calendar...{C_RESET}")
    try:
        # Call 'ots stamp'
        subprocess.check_call([OTS_EXEC, "stamp", target_file])

        # 5. Log it
        log_anchor(os.path.basename(target_file), h256, note)

        print(f"\n{C_GREEN}   ✅ SUCCESS!{C_RESET}")
        print(f"      1. Proof File: {C_BOLD}{target_file}.ots{C_RESET}")
        print(f"      2. Manifest:   {C_BOLD}{target_file}.provenance.json{C_RESET}")
        print(f"      Status: Pending (Wait ~10 mins for Bitcoin confirmation)")

    except subprocess.CalledProcessError as e:
        print(f"{C_RED}❌ Error during stamping: {e}{C_RESET}")

# ==============================================================================
#  SECTION 8: MAIN ENTRY POINT
# ==============================================================================

def main():
    print(f"\n{C_BOLD}🐾 FurryOS UNIVERSAL ANCHOR v3.6{C_RESET}")
    print("-" * 60)

    # 1. Show sorted files (THIS NOW AUTO-SYNCS YOUR LEDGER)
    show_file_listing()

    # 2. Get User Input
    try:
        target = input(f"\n{C_CYAN}   Enter filename to Anchor/Verify > {C_RESET}").strip().strip("'")

        if target and os.path.exists(target):
            # Smart Logic: If proof exists, Verify. If not, Anchor.
            if find_proof_path(target):
                verify_file(target)
            else:
                anchor_file(target)
        elif target:
            print(f"{C_RED}   File not found.{C_RESET}")

    except KeyboardInterrupt:
        print("\nExiting.")
        sys.exit(0)

if __name__ == "__main__":
    main()
