#!/usr/bin/env bash
set -euo pipefail
test "${EUID:-$(id -u)}" -eq 0 || { echo "run as root"; exit 1; }
id -u aivfccs >/dev/null 2>&1 || useradd --system --home /var/lib/aivf-ccs --shell /usr/sbin/nologin aivfccs
install -d -o aivfccs -g aivfccs -m 700 /var/lib/aivf-ccs /var/lib/aivf-ccs/keys
install -d -o aivfccs -g aivfccs -m 750 /run/aivf-ccs
install -d -m 755 /opt/aivf-ccs /etc/aivf-ccs
python3 -m venv /opt/aivf-ccs/venv
/opt/aivf-ccs/venv/bin/pip install --upgrade pip
/opt/aivf-ccs/venv/bin/pip install ./aivf-ccs-verifier
install -m 600 deploy/ccs.env.example /etc/aivf-ccs/ccs.env
install -m 644 deploy/aivf-ccs.service /etc/systemd/system/aivf-ccs.service
systemctl daemon-reload
systemctl enable --now aivf-ccs.service
systemctl status --no-pager aivf-ccs.service
