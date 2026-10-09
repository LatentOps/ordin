"""Synthetic production component; static inspection only."""

import subprocess
from fixture_runtime import check_permission


def main():
    check_permission()
    subprocess.run(["fixture-deploy", "synthetic"], check=True)
