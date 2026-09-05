#!/usr/bin/env python3
"""
download_dataset.py — Downloads one of three supported IDS datasets
automatically so you don't have to find them manually.

Usage:
  python download_dataset.py --dataset nsl-kdd       (default, from GitHub mirror)
  python download_dataset.py --dataset unsw-nb15
  python download_dataset.py --dataset cicids2017
  python download_dataset.py --list                  (show all options)
"""

import os
import sys
import argparse
import urllib.request
import zipfile
import gzip
import shutil
from pathlib import Path

# Force UTF-8 output on Windows so Unicode symbols (✅ ❌ ↓ …) print correctly
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout = open(sys.stdout.fileno(), mode="w", encoding="utf-8", buffering=1)
if sys.stderr.encoding and sys.stderr.encoding.lower() != "utf-8":
    sys.stderr = open(sys.stderr.fileno(), mode="w", encoding="utf-8", buffering=1)

DATA_DIR = Path(__file__).parent / "data"

# ─── Dataset Registry ─────────────────────────────────────────────────────────

DATASETS = {
    "nsl-kdd": {
        "name":        "NSL-KDD (GitHub mirror)",
        "description": "Classic IDS benchmark — 5 classes (normal, dos, probe, r2l, u2r)",
        "files": [
            {
                "url":      "https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master/KDDTrain%2B.txt",
                "filename": "KDDTrain+.txt",
                "desc":     "Training set (125,973 records)",
            },
            {
                "url":      "https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master/KDDTest%2B.txt",
                "filename": "KDDTest+.txt",
                "desc":     "Test set (22,544 records)",
            },
        ],
        "train_file": "KDDTrain+.txt",
        "train_cmd":  "python main.py train --dataset data/KDDTrain+.txt",
    },

    "unsw-nb15": {
        "name":        "UNSW-NB15 (Modern replacement)",
        "description": "9 modern attack types — more realistic than NSL-KDD (2015)",
        "files": [
            {
                # Multiple mirrors listed — the downloader tries each in order
                "urls": [
                    "https://raw.githubusercontent.com/Nir-J/ML-Projects/master/UNSW-Network_Packet_Classification/UNSW_NB15_training-set.csv",
                    "https://raw.githubusercontent.com/oshoyemi/project/master/UNSW_NB15_training-set.csv",
                ],
                "filename": "UNSW_NB15_training-set.csv",
                "desc":     "Training set (175,341 records)",
            },
            {
                "urls": [
                    "https://raw.githubusercontent.com/Nir-J/ML-Projects/master/UNSW-Network_Packet_Classification/UNSW_NB15_testing-set.csv",
                    "https://raw.githubusercontent.com/oshoyemi/project/master/UNSW_NB15_testing-set.csv",
                ],
                "filename": "UNSW_NB15_testing-set.csv",
                "desc":     "Test set (82,332 records)",
            },
        ],
        "train_file": "UNSW_NB15_training-set.csv",
        "train_cmd":  "python main.py train --dataset data/UNSW_NB15_training-set.csv",
    },

    "cicids2017": {
        "name":        "CIC-IDS-2017",
        "description": "Modern dataset with DDoS, PortScan, BruteForce, Web Attacks",
        "files": [
            {
                "urls": [
                    # 73 MB Friday DDoS session — 225,745 records
                    "https://raw.githubusercontent.com/deathtaco1231/NetworkSecurityProject/main/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
                ],
                "filename": "cicids2017_sample.csv",
                "desc":     "Friday DDoS session (225,745 records, ~74 MB)",
            },
        ],
        "train_file": "cicids2017_sample.csv",
        "train_cmd":  "python main.py train --dataset data/cicids2017_sample.csv",
    },
}

# ─── Progress Reporter ────────────────────────────────────────────────────────

def _progress(block_num, block_size, total_size):
    downloaded = block_num * block_size
    if total_size > 0:
        pct = min(downloaded / total_size * 100, 100)
        mb  = downloaded / (1024 * 1024)
        total_mb = total_size / (1024 * 1024)
        bar = "█" * int(pct / 5) + "░" * (20 - int(pct / 5))
        print(f"\r  [{bar}] {pct:5.1f}%  {mb:.1f}/{total_mb:.1f} MB",
              end="", flush=True)
    else:
        mb = downloaded / (1024 * 1024)
        print(f"\r  Downloading… {mb:.1f} MB", end="", flush=True)


# ─── Downloader ───────────────────────────────────────────────────────────────

def download_dataset(key: str) -> bool:
    if key not in DATASETS:
        print(f"[!] Unknown dataset: {key}")
        print(f"    Available: {', '.join(DATASETS.keys())}")
        return False

    ds = DATASETS[key]
    DATA_DIR.mkdir(exist_ok=True)

    print(f"\n{'='*60}")
    print(f"  Dataset  : {ds['name']}")
    print(f"  About    : {ds['description']}")
    print(f"{'='*60}\n")

    success = True
    for f in ds["files"]:
        dest = DATA_DIR / f["filename"]

        if dest.exists():
            print(f"  ✅  Already exists: {f['filename']} — skipping")
            continue

        print(f"  ↓  {f['desc']}")

        # Support both legacy single-url and new multi-url (mirrors) entries
        mirrors = f.get("urls") or [f["url"]]
        downloaded = False
        for attempt, url in enumerate(mirrors, 1):
            label = f" (mirror {attempt}/{len(mirrors)})" if len(mirrors) > 1 else ""
            print(f"     {url}{label}")
            try:
                urllib.request.urlretrieve(url, dest, _progress)
                print()
                size_mb = dest.stat().st_size / (1024 * 1024)
                print(f"  ✅  Saved: data/{f['filename']} ({size_mb:.1f} MB)")
                downloaded = True
                break
            except Exception as e:
                print(f"\n  ⚠️  Mirror {attempt} failed: {e}")
                if dest.exists():
                    dest.unlink()  # remove partial file before retrying
                if attempt == len(mirrors):
                    print(f"  ❌  All mirrors failed for {f['filename']}")
                    success = False
                else:
                    print(f"     Trying next mirror…")

    if success:
        print(f"\n{'='*60}")
        print(f"  ✅  Download complete!")
        print(f"\n  To train your NIDS model, run:")
        print(f"  {ds['train_cmd']}")
        print(f"{'='*60}\n")
    else:
        _show_manual_instructions(key)

    return success


def _show_manual_instructions(key: str):
    """Show manual download steps if auto-download fails."""
    instructions = {
        "nsl-kdd": """
  Manual download steps for NSL-KDD:
  ─────────────────────────────────────
  Option 1 — GitHub (Recommended):
    1. Go to: https://github.com/jmnwong/NSL-KDD-Dataset
    2. Click on 'KDDTrain+.txt'
    3. Click 'Raw' button to view raw file
    4. Right-click → Save As → save to your nids/data/ folder

  Option 2 — Git clone:
    git clone https://github.com/jmnwong/NSL-KDD-Dataset.git
    cp NSL-KDD-Dataset/KDDTrain+.txt data/

  Option 3 — IMPACT (requires free account):
    https://www.impactcybertrust.org/dataset_view?idDataset=928
""",
        "unsw-nb15": """
  Manual download steps for UNSW-NB15:
  ─────────────────────────────────────
  Official site:
    https://research.unsw.edu.au/projects/unsw-nb15-dataset
    → Scroll to "Dataset Files" → download UNSW_NB15_training-set.csv

  GitHub mirror:
    https://github.com/AbertayMachineLearningGroup/network-IDS
    → Datasets/UNSW_NB15_training-set.csv
""",
        "cicids2017": """
  Manual download steps for CIC-IDS-2017:
  ─────────────────────────────────────────
  GitHub mirror (direct):
    https://github.com/deathtaco1231/NetworkSecurityProject
    → Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv (74 MB)
    → Click the file → click “Raw” → right-click → Save As
    → rename it to data/cicids2017_sample.csv

  Official site (all 8 day CSVs, requires free registration):
    https://www.unb.ca/cic/datasets/ids-2017.html
    → Fill short form → get link via email (free)
    → Download any CSV from MachineLearningCSV.zip
""",
    }
    print(instructions.get(key, ""))


# ─── List Command ─────────────────────────────────────────────────────────────

def list_datasets():
    print("\n  Available IDS Datasets:\n")
    for key, ds in DATASETS.items():
        files = ds["files"]
        print(f"  [{key}]")
        print(f"    Name : {ds['name']}")
        print(f"    About: {ds['description']}")
        for f in files:
            print(f"    File : {f['filename']} — {f['desc']}")
        print(f"    Train: {ds['train_cmd']}")
        print()


# ─── Status Check ─────────────────────────────────────────────────────────────

def check_status():
    print("\n  Dataset Status:\n")
    found_any = False
    for key, ds in DATASETS.items():
        for f in ds["files"]:
            dest = DATA_DIR / f["filename"]
            if dest.exists():
                size_mb = dest.stat().st_size / (1024 * 1024)
                print(f"  ✅  {f['filename']} ({size_mb:.1f} MB) — ready")
                found_any = True
            else:
                print(f"  ❌  {f['filename']} — not downloaded")

    if not found_any:
        print("\n  No datasets found in data/")
        print("  Run: python download_dataset.py --dataset nsl-kdd")
    print()


# ─── Entry ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Download IDS datasets for NIDS training",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python download_dataset.py                          # download NSL-KDD (default)
  python download_dataset.py --dataset nsl-kdd        # NSL-KDD from GitHub
  python download_dataset.py --dataset unsw-nb15      # UNSW-NB15 (modern)
  python download_dataset.py --dataset cicids2017     # CIC-IDS-2017
  python download_dataset.py --list                   # show all options
  python download_dataset.py --status                 # check what's downloaded
        """
    )
    parser.add_argument(
        "--dataset", "-d",
        choices=list(DATASETS.keys()),
        default="nsl-kdd",
        help="Which dataset to download (default: nsl-kdd)"
    )
    parser.add_argument("--list",   "-l", action="store_true",
                        help="List all available datasets")
    parser.add_argument("--status", "-s", action="store_true",
                        help="Check which datasets are already downloaded")
    parser.add_argument("--all",          action="store_true",
                        help="Download all datasets")

    args = parser.parse_args()

    if args.list:
        list_datasets()
    elif args.status:
        check_status()
    elif args.all:
        for key in DATASETS:
            download_dataset(key)
    else:
        download_dataset(args.dataset)


if __name__ == "__main__":
    main()
