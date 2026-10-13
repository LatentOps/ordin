"""Public OS/runtime metadata without subprocesses, hostname or network access."""

import os
import sys


def environment_label() -> str:
    release = ""
    windows_version = getattr(sys, "getwindowsversion", None)
    if windows_version is not None:
        version = windows_version()
        release = f" {version.major}.{version.minor}.{version.build}"
    elif hasattr(os, "uname"):
        release = " " + os.uname().release
    return f"Python {sys.version.split()[0]}; {sys.platform}{release}"
