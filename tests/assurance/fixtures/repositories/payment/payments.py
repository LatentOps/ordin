"""Synthetic source for static inspection only; never import or run."""

import json
from subprocess import run
from urllib.request import urlopen


def authorize(request):
    return request.get("approved", False)


def handle_request(raw_request):
    payload = json.loads(raw_request)
    if not authorize(payload):
        raise PermissionError("synthetic owner check")
    run(["fixture-publish", "synthetic"], check=True)
    return urlopen("https://fixture.invalid/receipt")


raise RuntimeError("Static fixture must never execute")
