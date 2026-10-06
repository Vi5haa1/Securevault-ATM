#!/usr/bin/env python3
"""
SecureVault ATM: Unified Seed Data CLI Entry Point
Usage:
  python backend/scripts/seed.py generate   - Generate synthetic seed_data.json deterministically
  python backend/scripts/seed.py load       - Idempotently load seed_data.json into database
  python backend/scripts/seed.py reset      - Clear seeded tables and reload clean dataset
  python backend/scripts/seed.py validate   - Run full 8-point validation suite
  python backend/scripts/seed.py all        - Run generate -> load -> validate in sequence
"""

import sys
import os
import argparse
import asyncio
from pathlib import Path

backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

from scripts.seed_faker import main as run_generator
from scripts.load_seed import load_seed_data
from scripts.validate_seed import run_validations, print_results


def cmd_generate():
    print("[*] Running synthetic seed data generator...")
    run_generator()


def cmd_load(reset: bool = False, confirm_yes: bool = False):
    print(f"[*] Loading seed data into database (reset={reset})...")
    asyncio.run(load_seed_data(reset=reset, confirm_yes=confirm_yes))


def cmd_validate() -> bool:
    print("[*] Running seed data validation suite...")
    results = asyncio.run(run_validations())
    return print_results(results)


def cmd_all(reset: bool = False, confirm_yes: bool = False):
    print("=" * 60)
    print("      SECUREVAULT ATM FULL SEED PIPELINE EXECUTION")
    print("=" * 60)
    cmd_generate()
    cmd_load(reset=reset, confirm_yes=confirm_yes)
    passed = cmd_validate()
    if not passed:
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="SecureVault ATM Seed Data CLI")
    parser.add_argument(
        "action",
        choices=["all", "generate", "load", "reset", "validate"],
        help="Pipeline action to execute"
    )
    parser.add_argument("--yes", "-y", action="store_true", help="Confirm reset non-interactively")
    args = parser.parse_args()

    if args.action == "generate":
        cmd_generate()
    elif args.action == "load":
        cmd_load(reset=False)
    elif args.action == "reset":
        cmd_load(reset=True, confirm_yes=args.yes)
    elif args.action == "validate":
        passed = cmd_validate()
        if not passed:
            sys.exit(1)
    elif args.action == "all":
        cmd_all(reset=False, confirm_yes=args.yes)


if __name__ == "__main__":
    main()
