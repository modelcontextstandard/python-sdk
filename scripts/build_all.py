#!/usr/bin/env python3
"""Build and/or check all publishable MCS packages.

Usage:
    python scripts/build_all.py --build              # build only
    python scripts/build_all.py --check              # check only
    python scripts/build_all.py --build --check      # build + check
    python scripts/build_all.py --build --clean       # clean + build
"""

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

PACKAGES = [
    "packages/core",
    "packages/drivers/mcs-driver-rest",
    "packages/drivers/mcs-driver-csv",
    "packages/drivers/mcs-driver-filesystem",
    "packages/adapters/mcs-adapter-http",
    "packages/adapters/mcs-adapter-localfs",
    "packages/adapters/mcs-adapter-smb",
    "packages/orchestrators/mcs-orchestrator-base",
    "packages/orchestrators/mcs-orchestrator-rest",
]

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "dist_all"


def _collect_artifacts() -> list[Path]:
    if not OUT_DIR.exists():
        return []
    return sorted(
        p for p in OUT_DIR.iterdir()
        if p.suffix == ".whl" or p.name.endswith(".tar.gz")
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Build and/or check all MCS packages.")
    parser.add_argument("--build", action="store_true", help="Build all packages into dist_all/.")
    parser.add_argument("--check", action="store_true", help="Run twine check on dist_all/ artifacts.")
    parser.add_argument("--clean", action="store_true", help="Remove dist_all/ before building.")
    args = parser.parse_args()

    if not args.build and not args.check:
        parser.print_help()
        return 1

    if args.build:
        if args.clean and OUT_DIR.exists():
            shutil.rmtree(OUT_DIR)
            print(f"Cleaned {OUT_DIR}")

        OUT_DIR.mkdir(exist_ok=True)

        failed = []
        for pkg in PACKAGES:
            pkg_path = ROOT / pkg
            print(f"\n{'='*60}")
            print(f"Building {pkg} ...")
            print(f"{'='*60}")
            result = subprocess.run(
                ["uv", "build", str(pkg_path), "--out-dir", str(OUT_DIR)],
                cwd=str(ROOT),
            )
            if result.returncode != 0:
                failed.append(pkg)

        artifacts = _collect_artifacts()
        print(f"\n{'='*60}")
        print(f"Built {len(artifacts)} artifacts in {OUT_DIR}")

        if failed:
            print(f"\nFAILED packages: {', '.join(failed)}")
            return 1

    if args.check:
        artifacts = _collect_artifacts()
        if not artifacts:
            print("No artifacts found -- nothing to check.")
            return 1
        print(f"\n{'='*60}")
        print(f"Running twine check on {len(artifacts)} artifacts ...")
        print(f"{'='*60}")
        result = subprocess.run(
            ["uvx", "twine", "check", *[str(a) for a in artifacts]],
            cwd=str(ROOT),
        )
        if result.returncode != 0:
            return 1
        print("\nAll checks passed.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
