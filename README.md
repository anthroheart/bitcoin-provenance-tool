# Bitcoin Provenance Tool 🛡️

A simple, stateful Python tool that anchors files to the Bitcoin Blockchain.

<img width="1920" height="1080" alt="screenshot" src="https://github.com/user-attachments/assets/f6d0e1fd-af31-4113-bfec-2113c4e9bd00" />

## 🧐 What is this?

This tool allows anyone to create an **immutable, cryptographic proof** that a specific file existed at a specific time.

Instead of relying on expensive services or complex "Web3" storage schemes (like Arweave or IPFS), this tool uses the **Bitcoin Blockchain**—the most secure and permanent ledger in history—to anchor your data.

**Key Features:**
*   **Free:** Uses OpenTimestamps (no transaction fees for you).
*   **Private:** Your file never leaves your computer. Only the cryptographic fingerprint (hash) is sent to the blockchain.
*   **Stateful:** The tool remembers the status of your files. It updates their status from `Anchored` → `Pending` → `Confirmed`.
*   **Standardized:** Generates a clean JSON artifact containing the Proof, Block Height, and Identity Key used.

## 🚀 Quick Start

### 1. Install Dependencies
You need Python 3 and two lightweight libraries:

```bash
pip install pynacl opentimestamps-client --user --break-system-packages
