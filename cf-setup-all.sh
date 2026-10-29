#!/usr/bin/env bash
set -euo pipefail

if [ "$EUID" -ne 0 ]; then
  echo "Error: Please run as root."
  exit 1
fi

SCRIPT_PATH="/root/cf-setup-all.sh"
APACHE_DIR="/usr/local/apache"
HTTPD_CONF="${APACHE_DIR}/conf/httpd.conf"
CONF_D_DIR="${APACHE_DIR}/conf.d"
CF_APACHE_CONF="${CONF_D_DIR}/cloudflare_remoteip.conf"
TMP_APACHE_CONF="/tmp/cloudflare_remoteip.conf.tmp"

APPLY_SCRIPT="/usr/local/bin/apply-cf-firewall.sh"
CSF_POST="/etc/csf/csfpost.sh"
SYSTEMD_OVERRIDE_DIR="/etc/systemd/system/csf.service.d"
SYSTEMD_OVERRIDE_FILE="${SYSTEMD_OVERRIDE_DIR}/override.conf"

APACHE_RELOAD_NEEDED=false

echo "=== [1/4] Ensuring Script Location & CronJob ==="

# 1. Ensure the script is located at /root/cf-setup-all.sh
CURRENT_SCRIPT_PATH="$(readlink -f "$0" 2>/dev/null || echo "$0")"
if [ "$CURRENT_SCRIPT_PATH" != "$SCRIPT_PATH" ]; then
  echo "-> Copying script to ${SCRIPT_PATH}..."
  cp "$CURRENT_SCRIPT_PATH" "$SCRIPT_PATH"
  chmod +x "$SCRIPT_PATH"
fi

# 2. Add cron job if it doesn't already exist
CRON_JOB="0 3 * * * ${SCRIPT_PATH} > /dev/null 2>&1"
if crontab -l 2>/dev/null | grep -Fq "$SCRIPT_PATH"; then
  echo "-> Cron job already exists. Skipping."
else
  echo "-> Adding nightly cron job to crontab..."
  (crontab -l 2>/dev/null || true; echo "$CRON_JOB") | crontab -
  echo "-> Cron job added successfully."
fi

echo ""
echo "=== [2/4] Configuring Apache mod_remoteip & LogFormat ==="

if [ ! -d "$APACHE_DIR" ]; then
  echo "Error: Apache directory $APACHE_DIR not found."
  exit 1
fi

# 1. Update LogFormat %h -> %a
if grep -q 'LogFormat "%h' "$HTTPD_CONF"; then
  echo "-> Updating LogFormat %h to %a in httpd.conf..."
  sed -i 's/LogFormat "%h /LogFormat "%a /g' "$HTTPD_CONF"
  APACHE_RELOAD_NEEDED=true
fi

# 2. Enable remoteip_module
if grep -q "#LoadModule remoteip_module" "$HTTPD_CONF"; then
  echo "-> Uncommenting remoteip_module in httpd.conf..."
  sed -i 's/#LoadModule remoteip_module/LoadModule remoteip_module/' "$HTTPD_CONF"
  APACHE_RELOAD_NEEDED=true
elif ! grep -q "LoadModule remoteip_module" "$HTTPD_CONF"; then
  echo "-> Adding LoadModule remoteip_module to httpd.conf..."
  echo "LoadModule remoteip_module modules/mod_remoteip.so" >> "$HTTPD_CONF"
  APACHE_RELOAD_NEEDED=true
fi

# 3. Ensure conf.d inclusion
if ! grep -q "Include.*conf.d/\*\.conf" "$HTTPD_CONF"; then
  echo "-> Adding Include directive for conf.d/*.conf..."
  echo "Include ${CONF_D_DIR}/*.conf" >> "$HTTPD_CONF"
  APACHE_RELOAD_NEEDED=true
fi

# 4. Fetch Cloudflare IPs for Apache trusted proxies
echo "-> Fetching Cloudflare IP ranges..."
CF_IPV4_RAW=$(curl -s https://www.cloudflare.com/ips-v4 || true)
CF_IPV6_RAW=$(curl -s https://www.cloudflare.com/ips-v6 || true)

if [ -z "$CF_IPV4_RAW" ]; then
  echo "Error: Failed to fetch Cloudflare IP ranges."
  exit 1
fi

mkdir -p "$CONF_D_DIR"

# 5. Generate Apache mod_remoteip config
{
  echo "# Cloudflare mod_remoteip Configuration"
  echo "RemoteIPHeader CF-Connecting-IP"
  for ip in $CF_IPV4_RAW$CF_IPV6_RAW; do
    echo "RemoteIPTrustedProxy $ip"
  done
} > "$TMP_APACHE_CONF"

if [ ! -f "$CF_APACHE_CONF" ] || ! cmp -s "$TMP_APACHE_CONF" "$CF_APACHE_CONF"; then
  echo "-> Updating ${CF_APACHE_CONF}..."
  mv "$TMP_APACHE_CONF" "$CF_APACHE_CONF"
  APACHE_RELOAD_NEEDED=true
else
  echo "-> Cloudflare Apache configuration is up to date."
  rm -f "$TMP_APACHE_CONF"
fi

# 6. Test syntax & reload Apache
"${APACHE_DIR}/bin/httpd" -t
if [ "$APACHE_RELOAD_NEEDED" = true ]; then
  echo "-> Reloading Apache service..."
  systemctl reload httpd
  echo "-> Apache reloaded successfully."
else
  echo "-> Apache reload skipped (no changes detected)."
fi

echo ""
echo "=== [3/4] Writing Firewall Application Script ==="

cat << 'EOF' > "$APPLY_SCRIPT"
#!/usr/bin/env bash
set -euo pipefail

CF_IPV4=$(curl -s https://www.cloudflare.com/ips-v4 \vert{} grep -E '^[0-9]' \vert{} tr '\n' ',' \vert{} sed 's/,$//')
CF_IPV6=$(curl -s https://www.cloudflare.com/ips-v6 \vert{} grep -E '^[0-9a-fA-F:]' \vert{} tr '\n' ',' \vert{} sed 's/,$//')

if [ -z "$CF_IPV4" ]; then
  echo "Error: Could not fetch Cloudflare IPv4 range."
  exit 1
fi

# Ensure base tables exist
nft add table ip filter 2>/dev/null || true

# 1. Create/Flush CF_RESTRICT chain
nft add chain ip filter CF_RESTRICT 2>/dev/null || true
nft flush chain ip filter CF_RESTRICT

# 2. Add ACCEPT rule for Cloudflare subnets on 80/443
nft add rule ip filter CF_RESTRICT ip saddr \{ $CF_IPV4 \} tcp dport \{ 80, 443 \} accept

# 3. Add LOG rule for non-Cloudflare connection attempts
nft add rule ip filter CF_RESTRICT tcp dport \{ 80, 443 \} limit rate 30/minute log prefix \"Firewall: *CF_BLOCK* \"

# 4. Add DROP rule
nft add rule ip filter CF_RESTRICT tcp dport \{ 80, 443 \} drop

# 5. Remove existing jump rules in INPUT to prevent duplicates
HANDLE=$(nft -a list chain ip filter INPUT 2>/dev/null | grep "CF_RESTRICT" | awk -F '# handle ' '{print $2}' || true)
if [ -n "$HANDLE" ]; then
  for h in $HANDLE; do
    nft delete rule ip filter INPUT handle "$h" 2>/dev/null || true
  done
fi

# 6. Prepend jump rule at position 0 of INPUT chain
nft insert rule ip filter INPUT position 0 tcp dport \{ 80, 443 \} counter jump CF_RESTRICT
EOF

chmod +x "$APPLY_SCRIPT"
echo "-> Created ${APPLY_SCRIPT}"

echo ""
echo "=== [4/4] Setting Up Systemd Service Overrides for CSF ==="

# 1. Clean csfpost.sh
cat << 'EOF' > "$CSF_POST
