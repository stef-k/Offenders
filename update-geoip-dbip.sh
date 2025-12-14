#!/bin/bash
# ==========================================================
# DB-IP GeoIP Database Auto-Updater
# Updates free Country + ASN MMDBs monthly
# ==========================================================

set -e
TARGET_DIR="/usr/share/GeoIP"
TMP_DIR="/tmp/dbip-update"
MONTH=$(date +%Y-%m)
COUNTRY_FILE="dbip-country-lite-${MONTH}.mmdb.gz"
ASN_FILE="dbip-asn-lite-${MONTH}.mmdb.gz"

mkdir -p "$TMP_DIR"
cd "$TMP_DIR"

echo "🌍 Updating DB-IP GeoIP databases for $MONTH..."

# Download both databases
wget -q --show-progress "https://download.db-ip.com/free/${COUNTRY_FILE}" || { echo "❌ Failed to download $COUNTRY_FILE"; exit 1; }
wget -q --show-progress "https://download.db-ip.com/free/${ASN_FILE}" || { echo "❌ Failed to download $ASN_FILE"; exit 1; }

# Decompress
gunzip -f "$COUNTRY_FILE"
gunzip -f "$ASN_FILE"

# Move to /usr/share/GeoIP
sudo mv -f dbip-country-lite-${MONTH}.mmdb "$TARGET_DIR/"
sudo mv -f dbip-asn-lite-${MONTH}.mmdb "$TARGET_DIR/"

# Update symlinks to always point to latest
sudo ln -sf "$TARGET_DIR/dbip-country-lite-${MONTH}.mmdb" "$TARGET_DIR/dbip-country-lite.mmdb"
sudo ln -sf "$TARGET_DIR/dbip-asn-lite-${MONTH}.mmdb" "$TARGET_DIR/dbip-asn-lite.mmdb"

# Cleanup
rm -rf "$TMP_DIR"

echo "✅ DB-IP databases updated successfully."
