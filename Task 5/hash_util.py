#!/usr/bin/env python3
"""
Task 5 – Hashing & Integrity Check Utility

Features:
1. Compute SHA-256, SHA-1, and MD5 for a given file.
2. Save baseline hashes into a JSON file (hashes.json).
3. On next run, compare the current file hashes with the stored ones.
4. If hashes differ, show a WARNING (integrity FAIL). If they match, show PASS.

Usage:
    # First run: create baseline from original.txt
    python hash_util.py original.txt

    # After tampering: check integrity of tampered.txt
    python hash_util.py tampered.txt
"""

import sys
import json
import hashlib
from pathlib import Path


HASHES_JSON = "hashes.json"


def compute_hashes(file_path: Path) -> dict:
    """
    Compute SHA-256, SHA-1, and MD5 hashes for the given file.
    Returns a dict with hex digests.
    """
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()

    with file_path.open("rb") as f:
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)

    return {
        "sha256": sha256.hexdigest(),
        "sha1": sha1.hexdigest(),
        "md5": md5.hexdigest(),
    }


def save_baseline(file_path: Path, hashes: dict, json_path: Path):
    """
    Save baseline hashes for the file into hashes.json.
    """
    data = {
        "baseline_file": str(file_path.name),
        "hashes": hashes,
    }
    with json_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
    print(f"[INFO] Baseline hashes saved to {json_path} for file '{file_path.name}'.")


def load_baseline(json_path: Path) -> dict:
    """
    Load baseline hashes from hashes.json.
    """
    with json_path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    return data


def compare_hashes(stored: dict, current: dict) -> bool:
    """
    Compare stored vs current hashes.
    Returns True if all match, False otherwise.
    Prints differences.
    """
    print("\n[INFO] Comparing hashes with baseline...")
    all_match = True
    for algo in ["sha256", "sha1", "md5"]:
        stored_val = stored.get(algo)
        current_val = current.get(algo)
        match = stored_val == current_val
        status = "MATCH" if match else "MISMATCH"
        print(f"  {algo.upper()}:")
        print(f"    Baseline: {stored_val}")
        print(f"    Current : {current_val}")
        print(f"    Result  : {status}")
        if not match:
            all_match = False
    return all_match


def main():
    if len(sys.argv) < 2:
        print("Usage: python hash_util.py <file>")
        print("Example:")
        print("  python hash_util.py original.txt")
        print("  python hash_util.py tampered.txt")
        sys.exit(1)

    file_path = Path(sys.argv[1])
    json_path = Path(HASHES_JSON)

    if not file_path.exists():
        print(f"[ERROR] File '{file_path}' does not exist.")
        sys.exit(1)

    print(f"[INFO] Computing hashes for: {file_path.name}")
    current_hashes = compute_hashes(file_path)

    # First run: hashes.json does not exist -> create baseline
    if not json_path.exists():
        print("[INFO] No existing hashes.json found. Creating baseline...")
        save_baseline(file_path, current_hashes, json_path)
        print("[RESULT] Baseline created. Integrity check will be possible on next run.")
        return

    # Next runs: hashes.json exists -> compare
    print(f"[INFO] Found existing {json_path}. Loading baseline...")
    baseline_data = load_baseline(json_path)
    stored_hashes = baseline_data.get("hashes", {})
    baseline_file = baseline_data.get("baseline_file", "unknown")

    print(f"[INFO] Baseline file recorded as: {baseline_file}")
    integrity_ok = compare_hashes(stored_hashes, current_hashes)

    if integrity_ok:
        print("\n[RESULT] Integrity check PASSED: file matches the baseline.")
    else:
        print("\n[WARNING] Integrity check FAILED: file does NOT match the baseline!")
        print("[WARNING] This suggests the file may have been tampered with.")


if __name__ == "__main__":
    main()
