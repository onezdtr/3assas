#!/bin/sh
# Build, install and start 3assas (tracer as root) and its agent (as the calling user).
set -eu
cd "$(dirname "$0")"
DIR=$(pwd)
USER_NAME=${SUDO_USER:-$(id -un)}
[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }
[ -f data/ip2asn.tsv.gz ] && [ -f data/dbip-country.csv.gz ] || { echo "data/ files missing, see README"; exit 1; }
sudo -u "$USER_NAME" cargo build --release
install -m 755 target/release/3assas /usr/local/bin/3assas
install -d /usr/local/share/3assas
install -m 644 data/ip2asn.tsv.gz data/dbip-country.csv.gz /usr/local/share/3assas/
install -m 644 systemd/3assas.service /etc/systemd/system/
sed "s|@USER@|$USER_NAME|; s|@DIR@|$DIR|" systemd/3assas-agent.service > /etc/systemd/system/3assas-agent.service
systemctl daemon-reload
systemctl enable --now 3assas.service 3assas-agent.service
systemctl restart 3assas.service 3assas-agent.service
echo "page: http://127.0.0.1:4545"
