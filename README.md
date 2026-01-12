# Bitcoin Provenance Tool 🛡️

A simple, stateful Python tool that anchors files to the Bitcoin Blockchain.

<img width="1920" height="1080" alt="screenshot" src="https://github.com/user-attachments/assets/1319327d-be85-4171-905b-e480da76d682" />

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
```

## MIT License

Copyright (c) 2026 Anthro Entertainment LLC

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
