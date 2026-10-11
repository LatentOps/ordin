"""Bounded process I/O and lifetime. Isolation is supplied by the reviewed broker."""

import hashlib
import os
import subprocess
import threading
import time

from .codex_security._suspended_process import launch_managed_process


def run_test_process(runtime, data, cancel):
    started = time.monotonic()
    process = tree = None
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    counts = {"stdout": 0, "stderr": 0}
    hashes = {"stdout": hashlib.sha256(), "stderr": hashlib.sha256()}
    overflow = threading.Event()
    writer_error = threading.Event()
    threads = []
    status = "error"
    exit_code = None

    def read(stream, name):
        try:
            while True:
                chunk = stream.read(1024)
                if not chunk:
                    break
                counts[name] += len(chunk)
                hashes[name].update(chunk)
                if counts[name] > runtime.max_output_bytes:
                    overflow.set()
                    break
                if name == "stdout":
                    buffers[name].extend(chunk)
        except (OSError, ValueError):
            writer_error.set()

    try:
        if cancel.is_set():
            status = "canceled"
        else:
            environment = {
                key: os.environ[key] for key in ("SYSTEMROOT", "WINDIR") if key in os.environ
            }
            environment.update(
                {
                    "HOME": str(runtime.private_home),
                    "USERPROFILE": str(runtime.private_home),
                    "TMP": str(runtime.private_home),
                    "TEMP": str(runtime.private_home),
                }
            )
            process, tree = launch_managed_process(
                [str(runtime.executable), *runtime.arguments],
                cwd=runtime.trusted_cwd,
                env=environment,
                stdin=subprocess.PIPE,
            )
            for name in ("stdout", "stderr"):
                thread = threading.Thread(
                    target=read, args=(getattr(process, name), name), daemon=True
                )
                threads.append(thread)
                thread.start()

            def write():
                assert process is not None and process.stdin is not None
                try:
                    process.stdin.write(data)
                    process.stdin.flush()
                except (OSError, ValueError):
                    writer_error.set()
                finally:
                    try:
                        process.stdin.close()
                    except (OSError, ValueError):
                        pass

            sender = threading.Thread(target=write, daemon=True)
            threads.append(sender)
            sender.start()
            deadline = started + runtime.timeout_ms / 1000
            while True:
                if cancel.is_set():
                    status = "canceled"
                    break
                if overflow.is_set():
                    status = "output_limit"
                    break
                if time.monotonic() >= deadline:
                    status = "timeout"
                    break
                if process.poll() is not None:
                    exit_code = process.returncode
                    status = "completed" if exit_code == 0 else "refused"
                    break
                time.sleep(0.01)
    except (OSError, ValueError):
        status = "unavailable"
    finally:
        if tree is not None:
            try:
                tree.close()  # Includes descendants retaining inherited output pipes.
            except OSError:
                status = "error"  # Unconfirmed cleanup cannot produce a completed receipt.
        if process is not None:
            if process.poll() is None:
                try:
                    process.kill()
                except OSError:
                    pass
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
            exit_code = process.returncode
            for thread in threads:
                thread.join(timeout=2)
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
            if overflow.is_set():
                status = "output_limit"
            elif writer_error.is_set() and status == "completed":
                status = "error"
    return {
        "status": status,
        "exit_code": exit_code,
        "stdout": bytes(buffers["stdout"]),
        "stdout_digest": hashes["stdout"].hexdigest(),
        "stderr_digest": hashes["stderr"].hexdigest(),
        "stdout_bytes": counts["stdout"],
        "stderr_bytes": counts["stderr"],
        "elapsed_ms": (time.monotonic() - started) * 1000,
    }
