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
    # Core (no MCS dependencies)
    "packages/core",
    # Types (zero-dependency type packages)
    "packages/types/mcs-types-http",
    "packages/types/mcs-types-cache",
    # Adapters (depend on core at most)
    "packages/adapters/mcs-adapter-http",
    "packages/adapters/mcs-adapter-localfs",
    "packages/adapters/mcs-adapter-smb",
    "packages/adapters/mcs-adapter-imap",
    "packages/adapters/mcs-adapter-smtp",
    # Auth (mcs-auth first, then providers)
    "packages/auth/mcs-auth",
    "packages/auth/mcs-auth-auth0",
    "packages/auth/mcs-auth-oauth",
    "packages/auth/mcs-auth-linkauth",
    # Drivers (depend on core + adapters)
    "packages/drivers/mcs-driver-rest",
    "packages/drivers/mcs-driver-csv",
    "packages/drivers/mcs-driver-filesystem",
    "packages/drivers/mcs-driver-mailread",
    "packages/drivers/mcs-driver-mailsend",
    "packages/drivers/mcs-driver-mail",
    # Inspector (depends on drivers)
    "packages/inspector",
    # Orchestrators
    "packages/orchestrators/mcs-orchestrator-base",
    "packages/orchestrators/mcs-orchestrator-rest",
]

# Required files for PyPI publishing
REQUIRED_FILES = ["LICENSE", "README.md"]

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "dist_all"


def _collect_artifacts() -> list[Path]:
    if not OUT_DIR.exists():
        return []
    return sorted(
        p for p in OUT_DIR.iterdir()
        if p.suffix == ".whl" or p.name.endswith(".tar.gz")
    )


def _preflight_check(packages: list[str]) -> list[str]:
    """Check all packages for required files before building.

    Returns list of error messages. Empty list means all checks passed.
    """
    errors = []
    for pkg in packages:
        pkg_path = ROOT / pkg
        if not pkg_path.exists():
            errors.append(f"{pkg}: package directory does not exist")
            continue
        if not (pkg_path / "pyproject.toml").exists():
            errors.append(f"{pkg}: missing pyproject.toml")
            continue
        for required in REQUIRED_FILES:
            if not (pkg_path / required).exists():
                errors.append(f"{pkg}: missing {required}")
    return errors


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
        # Preflight: check all packages before building any
        print(f"Preflight check for {len(PACKAGES)} packages ...")
        errors = _preflight_check(PACKAGES)
        if errors:
            print(f"\nPreflight FAILED — {len(errors)} issue(s):\n")
            for err in errors:
                print(f"  - {err}")
            print(f"\nFix these issues before building. Aborting.")
            return 1
        print("Preflight OK.\n")

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
