"""Run substantive coordinator tests in a newly owned disposable PG cluster.

Requires installed PostgreSQL binaries and optional psycopg/pytest. Starts no TCP
listener and never inspects, changes or stops an existing database/service.
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def main() -> int:
    pg_config = shutil.which("pg_config")
    if sys.platform != "linux" or pg_config is None:
        raise SystemExit("owned PostgreSQL fixture requires Linux and pg_config")
    directory = Path(
        os.environ.get("ORDIN_POSTGRES_BINDIR")
        or subprocess.check_output([pg_config, "--bindir"], text=True).strip()
    )
    # libpq development headers may advertise a version whose server binaries
    # are not installed. Discover installed server directories without touching
    # any running cluster or system service.
    if not all((directory / tool).is_file() for tool in ("initdb", "pg_ctl")):
        candidates = sorted(Path("/usr/lib/postgresql").glob("*/bin"), reverse=True)
        directory = next(
            (
                path
                for path in candidates
                if all((path / tool).is_file() for tool in ("initdb", "pg_ctl"))
            ),
            directory,
        )
    if not all((directory / tool).is_file() for tool in ("initdb", "pg_ctl")):
        raise SystemExit("installed PostgreSQL initdb and pg_ctl are required")
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="ordin-coordinator-pg-") as name:
        fixture = Path(name)
        fixture.chmod(0o700)
        commands = []
        if os.geteuid() == 0:
            import pwd

            owner = pwd.getpwnam("postgres")
            os.chown(fixture, owner.pw_uid, owner.pw_gid)
            commands = ["runuser", "-u", "postgres", "--"]
        data, sockets = fixture / "data", fixture / "socket"
        sockets.mkdir(mode=0o700)
        if commands:
            os.chown(sockets, owner.pw_uid, owner.pw_gid)

        def run(arguments):
            try:
                subprocess.run(
                    [*commands, *map(str, arguments)],
                    check=True,
                    timeout=60,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                )
            except subprocess.CalledProcessError as error:
                print(error.stdout.decode("utf-8", errors="replace"), file=sys.stderr)
                raise

        run(
            [
                directory / "initdb",
                "-D",
                data,
                "--auth-local=trust",
                "--auth-host=reject",
                "--no-instructions",
            ]
        )
        run(
            [
                directory / "pg_ctl",
                "-D",
                data,
                "-l",
                fixture / "server.log",
                "-o",
                f"-c listen_addresses='' -c unix_socket_directories='{sockets}' -p 56371",
                "-w",
                "start",
            ]
        )
        try:
            environment = dict(
                os.environ,
                ORDIN_COORDINATOR_TEST_PG_DSN=f"host={sockets} port=56371 user={'postgres' if commands else os.environ.get('USER', '')} dbname=postgres",
                ORDIN_COORDINATOR_TEST_PG_ALLOW_CREATE="owned-fixture",
            )
            tests = sorted(
                str(path.relative_to(root))
                for path in (root / "tests").glob("test_swarm_coordinator*.py")
            )
            return subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    "-q",
                    *tests,
                    "--tb=short",
                    "--basetemp=" + str(fixture / "pytest"),
                ],
                cwd=root,
                env=environment,
                check=False,
                timeout=600,
            ).returncode
        finally:
            run([directory / "pg_ctl", "-D", data, "-m", "fast", "-w", "stop"])


if __name__ == "__main__":
    raise SystemExit(main())
