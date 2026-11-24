#!/usr/bin/env python3
import argparse
import http.client
import ipaddress
import socket
import subprocess
import sys
import time
from datetime import datetime

TARGET = "192.168.56.10"
ALLOWED_NETWORKS = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("192.168.56.0/24"),
)

PORTS = (
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8765, 9200,
    11211, 27017,
)

WEB_PATHS = (
    "/admin",
    "/wp-login.php",
    "/phpmyadmin",
    "/.env",
    "/.git/config",
    "/../../etc/passwd",
    "/%2e%2e/%2e%2e/etc/passwd",
    "/index.php?id=1%27%20OR%20%271%27=%271",
    "/cgi-bin/test-cgi",
    "/xmlrpc.php",
    "/actuator/env",
    "/uploads/shell.php",
)

SSH_USERS = ("root", "admin", "test", "guest", "oracle", "postgres", "ubuntu")


def log(message):
    stamp = datetime.now().strftime("%H:%M:%S")
    print("[{}] {}".format(stamp, message), flush=True)


def check_target(address):
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        sys.exit("invalid target: {}".format(address))
    if not any(ip in network for network in ALLOWED_NETWORKS):
        sys.exit("refusing to target anything outside the local lab network (127.0.0.0/8, 192.168.56.0/24)")


def scan_ports(address, timeout, dry_run):
    log("port scan: probing {} TCP ports on {}".format(len(PORTS), address))
    found = []
    for port in PORTS:
        if dry_run:
            log("  would connect {}:{}".format(address, port))
            continue
        try:
            with socket.create_connection((address, port), timeout=timeout):
                found.append(port)
                log("  {}/tcp open".format(port))
        except OSError:
            pass
    if not dry_run:
        log("port scan complete: open ports {}".format(found or "none"))


def web_probes(address, port, count, delay, dry_run):
    log("web probe: {} requests to {}:{}".format(count, address, port))
    for index in range(count):
        path = WEB_PATHS[index % len(WEB_PATHS)]
        if dry_run:
            log("  would GET http://{}:{}{}".format(address, port, path))
        else:
            connection = http.client.HTTPConnection(address, port, timeout=3)
            try:
                connection.request("GET", path, headers={"User-Agent": "lab-simulator/1.0"})
                response = connection.getresponse()
                response.read()
                log("  GET {} -> {}".format(path, response.status))
            except (OSError, http.client.HTTPException) as error:
                log("  GET {} -> {}".format(path, error))
            finally:
                connection.close()
        if index + 1 < count:
            time.sleep(delay)


def ssh_failures(address, count, delay, dry_run):
    log("ssh failures: {} attempts to {}".format(count, address))
    for index in range(count):
        user = SSH_USERS[index % len(SSH_USERS)]
        if dry_run:
            log("  would attempt ssh {}@{} with no valid key".format(user, address))
        else:
            command = [
                "ssh",
                "-o", "BatchMode=yes",
                "-o", "ConnectTimeout=3",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "PreferredAuthentications=publickey",
                "-o", "IdentitiesOnly=yes",
                "-i", "/nonexistent-lab-key",
                "{}@{}".format(user, address),
                "true",
            ]
            try:
                result = subprocess.run(
                    command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8
                )
                detail = result.stderr.decode(errors="replace").strip().splitlines()
                log("  ssh {}@{} -> rc={} {}".format(
                    user, address, result.returncode, detail[-1] if detail else ""
                ))
            except subprocess.TimeoutExpired:
                log("  ssh {}@{} -> timeout".format(user, address))
        if index + 1 < count:
            time.sleep(delay)


def main():
    parser = argparse.ArgumentParser(
        description="Simulate scan/probe/failed-login traffic against the local test VM only."
    )
    parser.add_argument("--target", default=TARGET, help="local VM IP (default: %(default)s)")
    parser.add_argument(
        "--scenario",
        choices=("port-scan", "web-probe", "ssh-fail", "all"),
        default="all",
        help="which simulation to run (default: %(default)s)",
    )
    parser.add_argument("--count", type=int, default=5, help="requests per scenario (default: %(default)s)")
    parser.add_argument("--delay", type=float, default=1.0, help="seconds between requests (default: %(default)s)")
    parser.add_argument("--web-port", type=int, default=8765, help="web port on the VM (default: %(default)s)")
    parser.add_argument("--timeout", type=float, default=0.5, help="connect timeout in seconds (default: %(default)s)")
    parser.add_argument("--dry-run", action="store_true", help="print actions without sending traffic")
    args = parser.parse_args()

    check_target(args.target)
    log("target {} scenario {} dry-run={}".format(args.target, args.scenario, args.dry_run))

    if args.scenario in ("port-scan", "all"):
        scan_ports(args.target, args.timeout, args.dry_run)
    if args.scenario in ("web-probe", "all"):
        web_probes(args.target, args.web_port, args.count, args.delay, args.dry_run)
    if args.scenario in ("ssh-fail", "all"):
        ssh_failures(args.target, args.count, args.delay, args.dry_run)

    log("done. Check VM logs: sudo journalctl -u ssh -n 50, or the terminal running http.server")


if __name__ == "__main__":
    main()
