"""bench_guest_run (scripts/lib.sh) against a stand-in for a VM: a temporary home on this machine, reached through a
stand-in for SSH that breaks calls, as a dropped session does. The script must run to its end anyway, once, its whole
output must come back in order, and its exit status must be the one returned."""

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

LIB = Path(__file__).resolve().parents[1] / "lib.sh"

# the stand-in for SSH: runs the remote command in FAKE_HOME; every second call fails as a broken session does
FLAKY_SSH = """#!/usr/bin/env bash
n=$(cat "$FAKE_HOME/.calls" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" > "$FAKE_HOME/.calls"
if [ $((n % 2)) -eq 0 ]; then echo "Connection reset by peer (call $n)" >&2; exit 255; fi
HOME="$FAKE_HOME" exec bash -c "$1"
"""

# the stand-in for SSH whose first call runs its command and then reports a broken session, as when the session breaks
# after the VM ran the command and before its answer came back
LOST_REPLY_SSH = """#!/usr/bin/env bash
n=$(cat "$FAKE_HOME/.calls" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" > "$FAKE_HOME/.calls"
HOME="$FAKE_HOME" bash -c "$1"; rc=$?
if [ "$n" -eq 1 ]; then echo "Connection reset by peer after the command ran (call $n)" >&2; exit 255; fi
exit $rc
"""

# the stand-in for SSH that runs nothing: it keeps each remote command (.call1, .call2, ...) and answers the calls after
# the first as if the script had ended with status 0
RECORDING_SSH = """#!/usr/bin/env bash
n=$(cat "$FAKE_HOME/.calls" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" > "$FAKE_HOME/.calls"
printf '%s' "$1" > "$FAKE_HOME/.call$n"
[ "$n" -eq 1 ] || printf '\\n@@bench-rc@@0'
"""

# octets outside ASCII too, read in several calls: the output is read on from an offset in octets (tail -c), and a
# length in characters would read some of it twice
GUEST_SCRIPT = """for i in 1 2 3 4 5; do echo "line $i — naïve"; sleep 2; done
printf 'no newline at the end'
exit 3
"""
EXPECTED = "".join(f"line {i} — naïve\n" for i in range(1, 6)) + "no newline at the end\n"


def guest_run(tmp, ssh_script, guest_script, timeout_s, extra_env=None):
    """Runs bench_guest_run with the stand-in SSH_SCRIPT; returns the run, the VM's home and the log."""
    home = Path(tmp, "vm")
    home.mkdir()
    ssh = Path(tmp, "ssh")
    ssh.write_text(ssh_script)
    ssh.chmod(0o755)
    log = Path(tmp, "ssh.log")
    # a UTF-8 locale, as on most machines, in which bash counts a string's length in characters
    env = dict(os.environ, FAKE_HOME=str(home), BENCH_GUEST_TIMEOUT=str(timeout_s), LC_ALL="C.UTF-8")
    # never BENCH_CHAOS_SSH from the caller's environment: the stand-ins run their commands on this machine, and the
    # test's commands would kill this machine's SSH sessions
    env.pop("BENCH_CHAOS_SSH", None)
    env.update(extra_env or {})
    run = subprocess.run(
        ["bash", "-c", f'. "{LIB}" && bench_guest_run "$1" "$2" "$3"', "-", str(log), guest_script, str(ssh)],
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    return run, home, log


def run_dirs(home):
    return sorted(home.glob("bench-run-*"))


class GuestRunTest(unittest.TestCase):
    def test_survives_broken_calls(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, home, log = guest_run(tmp, FLAKY_SSH, GUEST_SCRIPT, 60)
            self.assertEqual(run.returncode, 3, run.stderr)
            self.assertEqual(run.stdout, EXPECTED, run.stdout)
            calls = int(Path(home, ".calls").read_text())
            failures = log.read_text().count("Connection reset by peer")
            self.assertGreaterEqual(failures, 2, "the stand-in broke no call")
            self.assertEqual(failures, calls // 2)
            self.assertEqual(len(run_dirs(home)), 1)
            self.assertEqual(Path(run_dirs(home)[0], "rc").read_text().strip(), "3")

    def test_started_once_when_the_answer_is_lost(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, home, log = guest_run(tmp, LOST_REPLY_SSH, "echo started >> ~/starts\necho done\nexit 0", 60)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(run.stdout, "done\n", run.stdout)
            self.assertIn("try 1 of 3 failed", log.read_text())
            self.assertEqual(Path(home, "starts").read_text(), "started\n", "the script ran more than once")
            self.assertEqual(len(run_dirs(home)), 1)

    def test_chaos_commands_are_valid_shell(self):
        # BENCH_CHAOS_SSH=1 is for a real VM only: here the stand-in keeps the commands and runs none of them
        with tempfile.TemporaryDirectory() as tmp:
            run, home, log = guest_run(tmp, RECORDING_SSH, "echo hi", 60, {"BENCH_CHAOS_SSH": "1"})
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertIn("BENCH_CHAOS_SSH=1", log.read_text())
            start = Path(home, ".call1").read_text()
            for part in ("mkdir ~/bench-run-", "sleep 20", "t0 + 40", "pkill -KILL -u $(id -u) -x 'sshd|sshd-session'"):
                self.assertIn(part, start)
            # the command, and each script it gives bash -c (the workload's wrapper, the session breaker), parse
            scripts = [start, *re.findall(r"bash -c '([^']*)'", start)]
            self.assertEqual(len(scripts), 3, start)
            for s in scripts:
                check = subprocess.run(["bash", "-n"], input=s, text=True, capture_output=True, check=False)
                self.assertEqual(check.returncode, 0, f"{s}\n{check.stderr}")

    def test_timeout(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _, log = guest_run(tmp, '#!/usr/bin/env bash\nHOME="$FAKE_HOME" exec bash -c "$1"\n', "sleep 8", 3)
            self.assertEqual(run.returncode, 255)
            self.assertIn("did not end within 3 s", log.read_text())


if __name__ == "__main__":
    unittest.main()
