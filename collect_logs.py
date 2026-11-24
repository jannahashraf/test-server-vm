#!/usr/bin/env python3
import argparse
import json
import re
import subprocess
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

SSH_JOURNAL = "sudo journalctl -u ssh --no-pager -o short-iso -n 1000"
WEB_LOG = "cat /home/vagrant/web_access.log 2>/dev/null || true"
DOCKER_WEB_LOG = ["docker", "compose", "logs", "--tail", "1000", "web"]
DOCKER_PREFIX = re.compile(r"^web\s+\|\s*", re.MULTILINE)

SUSPICIOUS_PATHS = (
    "/admin", "/wp-login.php", "/phpmyadmin", "/.env", "/.git/config",
    "/../../etc/passwd", "/%2e%2e/%2e%2e/etc/passwd", "/xmlrpc.php",
    "/cgi-bin/test-cgi", "/actuator/env", "/uploads/shell.php",
)

SSH_PATTERNS = (
    (re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)"), "invalid_user"),
    (re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)"), "failed_password"),
    (re.compile(r"Connection closed by invalid user (?P<user>\S+) (?P<ip>[\d.]+)"), "preauth_disconnect"),
    (re.compile(r"Accepted publickey for (?P<user>\S+) from (?P<ip>[\d.]+)"), "accepted_publickey"),
)

WEB_PATTERN = re.compile(
    r'^(?P<ip>[\d.]+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<proto>[^"]+)" (?P<status>\d+)'
)

SIM_WEB = re.compile(r"GET (?P<path>\S+) -> (?P<result>.+)$")
SIM_SSH = re.compile(r"ssh (?P<user>\S+)@(?P<ip>[\d.]+) -> (?P<result>.+)$")
SIM_PORT = re.compile(r"(?P<port>\d+)/tcp open$")


def vm_read(command):
    result = subprocess.run(
        ["vagrant", "ssh", "-c", command],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        timeout=90,
    )
    if result.returncode != 0:
        print("warning: vagrant ssh returned {}: {}".format(
            result.returncode, result.stderr.strip()
        ), file=sys.stderr)
    return result.stdout


def docker_web_read():
    try:
        result = subprocess.run(
            DOCKER_WEB_LOG,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            universal_newlines=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return DOCKER_PREFIX.sub("", result.stdout)


def journal_timestamp(line):
    parts = line.split(maxsplit=1)
    return parts[0] if parts and "T" in parts[0] else ""


def parse_ssh(lines):
    events = []
    for line in lines:
        if "sshd[" not in line:
            continue
        for pattern, event_type in SSH_PATTERNS:
            match = pattern.search(line)
            if match:
                events.append({
                    "timestamp": journal_timestamp(line),
                    "source": "vm_ssh",
                    "event_type": event_type,
                    "source_ip": match.group("ip"),
                    "user": match.group("user"),
                    "raw": line.strip(),
                })
                break
    return events


def parse_web(lines):
    events = []
    for line in lines:
        match = WEB_PATTERN.match(line)
        if not match:
            continue
        path = match.group("path")
        events.append({
            "timestamp": match.group("ts"),
            "source": "vm_web",
            "event_type": "web_request",
            "source_ip": match.group("ip"),
            "method": match.group("method"),
            "path": path,
            "status": int(match.group("status")),
            "suspicious": path in SUSPICIOUS_PATHS,
            "raw": line.strip(),
        })
    return events


def parse_simulator(lines):
    events = []
    for line in lines:
        match = SIM_WEB.search(line)
        if match:
            events.append({
                "timestamp": line[1:9] if line.startswith("[") else "",
                "source": "host_simulator",
                "event_type": "simulated_web_request",
                "path": match.group("path"),
                "result": match.group("result"),
                "raw": line.strip(),
            })
            continue
        match = SIM_SSH.search(line)
        if match:
            events.append({
                "timestamp": line[1:9] if line.startswith("[") else "",
                "source": "host_simulator",
                "event_type": "simulated_ssh_attempt",
                "source_ip": match.group("ip"),
                "user": match.group("user"),
                "result": match.group("result"),
                "raw": line.strip(),
            })
            continue
        match = SIM_PORT.search(line)
        if match:
            events.append({
                "timestamp": line[1:9] if line.startswith("[") else "",
                "source": "host_simulator",
                "event_type": "simulated_open_port",
                "port": int(match.group("port")),
                "raw": line.strip(),
            })
    return events


def write_text(path, lines):
    path.write_text("".join(lines), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(
        description="Collect simulated-attack logs from the Docker web container and local test VM into a dataset."
    )
    parser.add_argument("--output-dir", default="logs", help="folder for collected logs (default: %(default)s)")
    parser.add_argument("--simulator-log", help="optional host simulator log to merge")
    parser.add_argument("--include-accepted", action="store_true", help="include successful SSH logins")
    args = parser.parse_args()

    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    ssh_text = vm_read(SSH_JOURNAL)
    docker_web_text = docker_web_read()
    web_text = docker_web_text if docker_web_text is not None else vm_read(WEB_LOG)
    ssh_lines = [line for line in ssh_text.splitlines(True) if not line.startswith("Warning:")]
    web_lines = [line for line in web_text.splitlines(True) if not line.startswith("Warning:")]

    sim_lines = []
    if args.simulator_log:
        sim_lines = Path(args.simulator_log).read_text(encoding="utf-8").splitlines(True)

    write_text(output / "ssh_{}.log".format(stamp), ssh_lines)
    write_text(output / "web_{}.log".format(stamp), web_lines)
    if sim_lines:
        write_text(output / "simulator_{}.log".format(stamp), sim_lines)

    events = parse_ssh(ssh_lines) + parse_web(web_lines) + parse_simulator(sim_lines)
    if not args.include_accepted:
        events = [event for event in events if event.get("event_type") != "accepted_publickey"]
    events.sort(key=lambda event: (event.get("timestamp", ""), event.get("source", "")))

    dataset = output / "dataset_{}.jsonl".format(stamp)
    with dataset.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, sort_keys=True) + "\n")

    counts = Counter(event.get("event_type", "unknown") for event in events)
    summary = output / "summary_{}.txt".format(stamp)
    summary.write_text(
        "Collected {} events\n".format(len(events))
        + "".join("{}: {}\n".format(name, count) for name, count in sorted(counts.items())),
        encoding="utf-8",
    )

    print("Saved {} events to {}".format(len(events), dataset))
    for name, count in sorted(counts.items()):
        print("  {}: {}".format(name, count))


if __name__ == "__main__":
    main()
