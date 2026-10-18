#!/usr/bin/env python3
"""
SecurePass — Root Python Automated Test Suite Runner
Cybersecurity Internship Project: Task 1

Executes all 34 unit tests verifying scoring tiers, entropy mathematics,
dictionary checks, pattern detection, and privacy guarantees.
"""
import sys
import unittest
from pathlib import Path

# Add root directory to sys.path
ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=str(ROOT_DIR / "tests"), pattern="test_*.py")
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
