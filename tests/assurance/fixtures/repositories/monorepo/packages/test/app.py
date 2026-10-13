"""Synthetic test component; static inspection only."""

from pathlib import Path


def main():
    Path("fixture-build/output.txt").write_text("synthetic build output")
