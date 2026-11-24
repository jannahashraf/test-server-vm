#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get upgrade -y

apt-get install -y \
  ca-certificates \
  build-essential \
  curl \
  git \
  python3 \
  python3-pip \
  python3-venv

apt-get clean
