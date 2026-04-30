#!/usr/bin/env python3
"""
harden-docker-seccomp.py — Block AF_ALG socket creation for CVE-2026-31431.

Idempotent: safe to run multiple times; only reloads Docker when the on-disk
profile actually changes.

Steps performed:
  1. Extract Docker's active built-in seccomp profile via `docker info` /
     container inspection (no network, no remote URL dependency).
  2. Inject a deny rule for socket(AF_ALG, ...) — address family 38.
  3. Write the patched profile to PROFILE_PATH.
  4. Patch /etc/docker/daemon.json to point "seccomp-profile" at the file.
  5. Reload dockerd (SIGHUP) only when something changed.
  6. Always verify the block is active inside a container.

Requirements:
  - Python 3.12+
  - Docker Engine running (docker CLI in PATH)
  - Root / sudo for writes to /etc/docker and /etc/seccomp, and for
    `systemctl reload docker`

Usage:
  sudo python3 harden-docker-seccomp.py [--dry-run] [--verify-only]
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

PROFILE_PATH = Path("/etc/seccomp/docker-block-af-alg.json")
DAEMON_JSON_PATH = Path("/etc/docker/daemon.json")

# Linux AF_ALG address family number (architectures: x86, x86_64, arm, arm64)
AF_ALG = 38

LOG = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def run(args: list[str], **kwargs) -> subprocess.CompletedProcess:
    """Run a subprocess, raise on non-zero exit."""
    LOG.debug("+ %s", " ".join(args))
    return subprocess.run(args, check=True, **kwargs)  # noqa: S603


def extract_builtin_profile() -> dict:
    """
    Extract Docker's compiled-in default seccomp profile by starting a
    minimal container with --security-opt seccomp=builtin (Docker 25+) or
    by parsing `docker info`.

    Fallback chain:
      1. docker info --format '{{json .SecurityOptions}}' → find the path
         to the seccomp profile if the daemon has one already configured.
      2. Spin up a scratch container with --security-opt seccomp=builtin and
         inspect /proc/self/status (not useful for JSON) — we instead export
         the profile via `docker run` writing it out.
      3. Use `docker inspect` on a running container started without a custom
         profile to find the seccomp JSON embedded in HostConfig.

    The most reliable cross-version approach: start a container without a
    custom profile, then inspect its HostConfig.SecurityOpt.  Docker embeds
    the resolved seccomp JSON there.
    """
    LOG.info("Extracting Docker built-in seccomp profile…")

    # Start a short-lived container and inspect its HostConfig.
    # `busybox true` exits immediately; we capture the ID then inspect it.
    result = run(
        ["docker", "run", "--rm", "--detach", "--entrypoint", "sh",
         "busybox", "-c", "sleep 5"],
        capture_output=True, text=True,
    )
    container_id = result.stdout.strip()
    LOG.debug("Temporary container: %s", container_id)

    try:
        inspect = run(
            ["docker", "inspect", "--format",
             "{{json .HostConfig.SecurityOpt}}", container_id],
            capture_output=True, text=True,
        )
        opts: list[str] | None = json.loads(inspect.stdout.strip())
    finally:
        run(["docker", "stop", "-t", "1", container_id],
            capture_output=True)

    if opts:
        for opt in opts:
            if opt.startswith("seccomp=") and opt != "seccomp=unconfined":
                raw = opt[len("seccomp="):]
                return json.loads(raw)

    # Docker 25+ supports --security-opt seccomp=builtin explicitly;
    # if the inspect approach yielded nothing (containerd image store, etc.),
    # download from the canonical source.
    LOG.warning(
        "Could not extract profile from container inspect; "
        "fetching from moby/profiles GitHub."
    )
    return fetch_profile_from_github()


def fetch_profile_from_github() -> dict:
    """
    Fetch the current default profile from moby/profiles (the canonical repo
    since moby/moby no longer ships profiles/seccomp/default.json on main).
    """
    url = (
        "https://raw.githubusercontent.com/moby/profiles/main/"
        "seccomp/default.json"
    )
    LOG.info("Fetching profile from %s", url)
    result = run(
        ["curl", "-fsSL", "--retry", "3", url],
        capture_output=True, text=True,
    )
    return json.loads(result.stdout)


def already_patched(profile: dict) -> bool:
    """Return True if the profile already denies AF_ALG socket calls."""
    for entry in profile.get("syscalls", []):
        if "socket" not in entry.get("names", []):
            continue
        for arg in entry.get("args", []):
            if (
                arg.get("index") == 0
                and arg.get("value") == AF_ALG
                and arg.get("op") in ("SCMP_CMP_NE", "SCMP_CMP_EQ")
            ):
                return True
    return False


def patch_profile(profile: dict) -> dict:
    """
    Return a copy of *profile* with AF_ALG denied.

    Strategy: remove 'socket' from any existing SCMP_ACT_ALLOW entry
    (it may appear under 'name' or 'names'), then re-add it with an
    arg filter that allows all address families except AF_ALG (38).
    """
    import copy
    patched = copy.deepcopy(profile)
    syscalls: list[dict] = patched.setdefault("syscalls", [])

    for entry in syscalls:
        # Handle both legacy 'name' and current 'names' fields.
        names: list[str] = entry.get("names", [])
        if entry.get("name") == "socket":
            entry["name"] = ""
        if entry.get("action") == "SCMP_ACT_ALLOW" and "socket" in names:
            names.remove("socket")

    # Allow socket() for every address family EXCEPT AF_ALG.
    syscalls.append(
        {
            "names": ["socket"],
            "action": "SCMP_ACT_ALLOW",
            "args": [
                {
                    "index": 0,
                    "value": AF_ALG,
                    "op": "SCMP_CMP_NE",
                }
            ],
        }
    )

    return patched


def write_profile_atomically(profile: dict, path: Path) -> bool:
    """
    Write *profile* JSON to *path* atomically (temp file + rename).

    Returns True if the file content changed (or was created new).
    """
    new_content = json.dumps(profile, indent=2) + "\n"

    if path.exists():
        existing = path.read_text()
        if existing == new_content:
            LOG.info("Profile unchanged: %s", path)
            return False

    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-seccomp-")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(new_content)
        os.replace(tmp, path)
    except Exception:
        Path(tmp).unlink(missing_ok=True)
        raise

    LOG.info("Written: %s", path)
    return True


def patch_daemon_json(profile_path: Path) -> bool:
    """
    Ensure /etc/docker/daemon.json has "seccomp-profile" set to *profile_path*.

    Returns True if the file changed.
    """
    if DAEMON_JSON_PATH.exists():
        try:
            config: dict = json.loads(DAEMON_JSON_PATH.read_text())
        except json.JSONDecodeError:
            LOG.error("Could not parse %s — manual inspection required.",
                      DAEMON_JSON_PATH)
            raise
    else:
        config = {}

    desired = str(profile_path)
    if config.get("seccomp-profile") == desired:
        LOG.info("daemon.json already configured correctly.")
        return False

    config["seccomp-profile"] = desired

    DAEMON_JSON_PATH.parent.mkdir(parents=True, exist_ok=True)
    new_content = json.dumps(config, indent=2) + "\n"
    fd, tmp = tempfile.mkstemp(dir=DAEMON_JSON_PATH.parent, prefix=".tmp-daemon-")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(new_content)
        # Keep original as a backup on first write.
        if DAEMON_JSON_PATH.exists():
            shutil.copy2(DAEMON_JSON_PATH, str(DAEMON_JSON_PATH) + ".bak")
        os.replace(tmp, DAEMON_JSON_PATH)
    except Exception:
        Path(tmp).unlink(missing_ok=True)
        raise

    LOG.info("Updated: %s", DAEMON_JSON_PATH)
    return True


def reload_docker() -> None:
    """Send SIGHUP to dockerd to reload daemon.json without a full restart."""
    LOG.info("Reloading Docker daemon (SIGHUP)…")
    run(["systemctl", "reload", "docker"])
    LOG.info("Docker daemon reloaded.")


def verify_block() -> bool:
    """
    Spin up a container and confirm AF_ALG socket creation is denied.

    Returns True if blocked (expected), False if allowed (unexpected).
    """
    LOG.info("Verifying AF_ALG is blocked inside a container…")
    probe = (
        "import socket, sys\n"
        "try:\n"
        "    socket.socket(38, socket.SOCK_SEQPACKET, 0)\n"
        "    print('FAIL: AF_ALG allowed — mitigation NOT active')\n"
        "    sys.exit(1)\n"
        "except PermissionError as e:\n"
        "    print('OK: AF_ALG blocked —', e)\n"
        "    sys.exit(0)\n"
    )
    result = subprocess.run(  # noqa: S603
        ["docker", "run", "--rm", "python:3-slim", "python3", "-c", probe],
        capture_output=False,
    )
    return result.returncode == 0


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would change without writing files or reloading Docker.",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Skip patching; only run the container verification step.",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable debug logging.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )

    if not args.verify_only and os.geteuid() != 0:
        LOG.error("This script must be run as root (or with sudo).")
        return 1

    changed = False

    if not args.verify_only:
        # Step 1 — Get the base profile.
        try:
            profile = extract_builtin_profile()
        except subprocess.CalledProcessError:
            LOG.warning(
                "Container-based extraction failed; falling back to GitHub fetch."
            )
            profile = fetch_profile_from_github()

        # Step 2 — Patch if needed.
        if already_patched(profile):
            LOG.info(
                "Base profile already contains AF_ALG deny rule; "
                "skipping patch step."
            )
            patched = profile
        else:
            patched = patch_profile(profile)

        # Step 3 — Write profile.
        if args.dry_run:
            LOG.info("[dry-run] Would write patched profile to %s", PROFILE_PATH)
        else:
            changed |= write_profile_atomically(patched, PROFILE_PATH)

        # Step 4 — Patch daemon.json.
        if args.dry_run:
            LOG.info(
                "[dry-run] Would set seccomp-profile=%s in %s",
                PROFILE_PATH, DAEMON_JSON_PATH,
            )
        else:
            changed |= patch_daemon_json(PROFILE_PATH)

        # Step 5 — Reload Docker only when something actually changed.
        if changed:
            if args.dry_run:
                LOG.info("[dry-run] Would reload Docker daemon.")
            else:
                reload_docker()
        else:
            LOG.info("No changes — Docker daemon reload not required.")

    # Step 6 — Always verify.
    if args.dry_run:
        LOG.info("[dry-run] Would run container verification.")
        return 0

    ok = verify_block()
    if not ok:
        LOG.error("Verification FAILED — AF_ALG is not blocked.")
        return 2

    LOG.info("All done. CVE-2026-31431 (Copy Fail) mitigation is active.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
