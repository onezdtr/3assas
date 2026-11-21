#!/bin/sh
# Install and start 3assas (tracer as root) and its agent (as the calling user).
# From a git clone it builds first; from a release archive the binary is already there.
set -eu
cd "$(dirname "$0")"
DIR=$(pwd)
USER_NAME=${SUDO_USER:-$(id -un)}
SHARE=/usr/local/share/3assas
[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }
[ -r /sys/kernel/btf/vmlinux ] || { echo "this kernel has no BTF (/sys/kernel/btf/vmlinux): 3assas needs Linux >= 5.11 built with BTF"; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required (agent and web page)"; exit 1; }

if [ -x ./3assas ]; then
	BIN=./3assas
else
	sudo -u "$USER_NAME" cargo build --release
	BIN=target/release/3assas
fi

# IP → owner and country tables: from data/ when present, else downloaded once.
fetch() {
	echo "downloading $2"
	curl -fsSL -o "$SHARE/$1.tmp" "$2" && mv "$SHARE/$1.tmp" "$SHARE/$1"
}
install -d "$SHARE"
for f in ip2asn.tsv.gz dbip-country.csv.gz; do
	if [ -f "data/$f" ]; then
		install -m 644 "data/$f" "$SHARE/"
	elif [ ! -f "$SHARE/$f" ]; then
		case $f in
		ip2asn*) fetch "$f" https://iptoasn.com/data/ip2asn-combined.tsv.gz ;;
		# DB-IP publishes each month's file during the month: fall back to the previous one.
		*) fetch "$f" "https://download.db-ip.com/free/dbip-country-lite-$(date +%Y-%m).csv.gz" ||
			fetch "$f" "https://download.db-ip.com/free/dbip-country-lite-$(date -d '1 month ago' +%Y-%m).csv.gz" ;;
		esac
	fi
done

install -m 755 "$BIN" /usr/local/bin/3assas
install -d -m 755 /etc/3assas
install -m 644 systemd/3assas.service /etc/systemd/system/
sed "s|@USER@|$USER_NAME|; s|@DIR@|$DIR|" systemd/3assas-agent.service > /etc/systemd/system/3assas-agent.service
systemctl daemon-reload
systemctl enable --now 3assas.service 3assas-agent.service
systemctl restart 3assas.service 3assas-agent.service
echo "3assas is running. Page: http://127.0.0.1:4545"
