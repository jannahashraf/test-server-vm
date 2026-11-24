# Test Server VM (local only)

This folder holds a Vagrant definition for an Ubuntu 24.04 LTS server VM used to
test project work in isolation.

## Important

This folder is local only. Do not `git add`, `git commit`, or push any of it to
GitHub. It sits outside the `LBATH` repository, and its `.gitignore` ignores all
contents as a safety net.

## Prerequisites

Vagrant 2.4.9 and VirtualBox 7.2.22 are installed on this machine via Homebrew
(`brew install --cask virtualbox` and `brew install --cask vagrant`).

The box used is `bento/ubuntu-24.04` (Canonical stopped publishing Ubuntu
Vagrant images starting with 24.04).

## Usage

From this folder:

    vagrant up
    vagrant ssh

Other commands:

    vagrant halt
    vagrant reload
    vagrant destroy

## VM details

- OS: Ubuntu 24.04 LTS (Noble)
- Hostname: test-server-vm
- Resources: 2 CPUs, 2048 MB RAM
- Private network IP: 192.168.56.10
- Port 8765 on 127.0.0.1 of the host forwards to port 8765 in the VM (for the
  paper-hub server)
- No project folder is synced into the VM by default, so it stays isolated
- `bootstrap.sh` runs on first boot to install Python 3, pip, venv, git, curl,
  and build tools

## Attack simulation

`attack_simulator.py` runs on the host and generates scan/probe/failed-login
traffic only against the local VM. It refuses any target outside
`127.0.0.0/8` and `192.168.56.0/24`.

Start the web server in Docker on the host. It listens on `127.0.0.1:8766`
because Vagrant already forwards host port 8765 to the VM:

    docker compose up -d web

Probe the Docker web server with:

    python3 attack_simulator.py --scenario web-probe --target 127.0.0.1 --web-port 8766 --count 10

Then, from this folder on the host:

    python3 attack_simulator.py
    python3 attack_simulator.py --scenario port-scan
    python3 attack_simulator.py --scenario web-probe --count 10
    python3 attack_simulator.py --scenario ssh-fail --count 10 --delay 0.5
    python3 attack_simulator.py --dry-run

Inspect the generated events:

    sudo journalctl -u ssh -n 50 --no-pager
    sudo journalctl -u ssh | grep -E 'Invalid user|Failed password|preauth'
    docker compose logs --tail 50 web

## Log collection

`collect_logs.py` runs on the host, pulls SSH logs from the VM and web logs from
the Docker container (falling back to the VM web log), and writes timestamped
raw logs plus a JSONL dataset into `logs/` (ignored by git).
Optionally merge the simulator's own output by teeing it:

    python3 attack_simulator.py --count 10 | tee simulator.log
    python3 collect_logs.py --simulator-log simulator.log
    python3 collect_logs.py

Each run produces `logs/ssh_*.log`, `logs/web_*.log`, `logs/dataset_*.jsonl`,
and `logs/summary_*.txt`. Successful SSH logins are excluded by default; use
`--include-accepted` to keep them.
