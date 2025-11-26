#!/bin/bash

COLOR_GREEN="\e[32m"; COLOR_RED="\e[31m"
COLOR_YELLOW="\e[33m"; COLOR_BLUE="\e[34m"
COLOR_RESET="\e[0m"

FILE="$1"

if [ -z "$FILE" ]; then
    echo -e "${COLOR_RED}[!] Usage: $0 key.txt${COLOR_RESET}"
    exit 1
fi

RAW=$(cat "$FILE" | tr -d '\r')
TMP="/tmp/key_$$.pem"

if echo "$RAW" | grep -q "BEGIN PUBLIC KEY"; then
    echo -e "${COLOR_GREEN}[+] PEM public key detected.${COLOR_RESET}"
    echo "$RAW" > "$TMP"
elif echo "$RAW" | grep -q "BEGIN RSA PRIVATE KEY"; then
    echo -e "${COLOR_GREEN}[+] PEM RSA private key detected.${COLOR_RESET}"
    echo "$RAW" > "$TMP"
elif echo "$RAW" | grep -q "BEGIN PRIVATE KEY"; then
    echo -e "${COLOR_GREEN}[+] PKCS#8 private key detected.${COLOR_RESET}"
    echo "$RAW" > "$TMP"
elif echo "$RAW" | grep -q "ssh-rsa"; then
    echo -e "${COLOR_YELLOW}[+] OpenSSH RSA public key detected.${COLOR_RESET}"
    KEYBASE=$(echo "$RAW" | awk '{print $2}')
    echo "-----BEGIN PUBLIC KEY-----" > "$TMP"
    echo "$KEYBASE" >> "$TMP"
    echo "-----END PUBLIC KEY-----" >> "$TMP"
elif echo "$RAW" | grep -q "ssh-ed25519"; then
    echo -e "${COLOR_YELLOW}[+] OpenSSH Ed25519 public key detected.${COLOR_RESET}"
    TYPE="ECC Public"
    echo "$RAW" > "$TMP"
else
    echo -e "${COLOR_YELLOW}[*] No PEM header found → wrapping as PUBLIC KEY.${COLOR_RESET}"
    echo "-----BEGIN PUBLIC KEY-----" > "$TMP"
    echo "$RAW" >> "$TMP"
    echo "-----END PUBLIC KEY-----" >> "$TMP"
fi

RSA_PUB_OUT=$(openssl rsa -pubin -in "$TMP" -text -noout 2>/dev/null)
RSA_PRIV_OUT=$(openssl rsa -in "$TMP" -text -noout 2>/dev/null)

if [ ! -z "$RSA_PUB_OUT" ]; then
    TYPE="RSA Public"
    OUT="$RSA_PUB_OUT"
elif [ ! -z "$RSA_PRIV_OUT" ]; then
    TYPE="RSA Private"
    OUT="$RSA_PRIV_OUT"
fi

if [ -z "$TYPE" ]; then
    ECC_PUB_OUT=$(openssl ec -pubin -in "$TMP" -text -noout 2>/dev/null)
    ECC_PRIV_OUT=$(openssl ec -in "$TMP" -text -noout 2>/dev/null)

    if [ ! -z "$ECC_PUB_OUT" ]; then
        TYPE="ECC Public"
    elif [ ! -z "$ECC_PRIV_OUT" ]; then
        TYPE="ECC Private"
    fi
fi

if [ -z "$TYPE" ]; then
    echo -e "${COLOR_RED}[✖] Invalid key format (not RSA/ECC).${COLOR_RESET}"
    rm -f "$TMP"
    exit 1
fi

echo -e "${COLOR_GREEN}[✔] Key type: $TYPE${COLOR_RESET}"

if echo "$OUT" | grep -q "Public-Key"; then
    BITS=$(echo "$OUT" | grep "Public-Key" | grep -o "[0-9]\+ bit")
    echo -e "${COLOR_BLUE}[+] Key length: ${COLOR_RESET}$BITS"
fi

JSON_FILE="key_report_$(date +%s).json"
echo "{
  \"type\": \"$TYPE\",
  \"length\": \"$BITS\",
  \"file\": \"$FILE\",
  \"timestamp\": \"$(date -Iseconds)\"
}" > "$JSON_FILE"

echo -e "${COLOR_YELLOW}[+] JSON report created: $JSON_FILE${COLOR_RESET}"

HASH=$(sha256sum "$TMP" | awk '{print $1}')
echo -e "${COLOR_BLUE}[+] Key SHA-256: $HASH${COLOR_RESET}"
echo -e "${COLOR_YELLOW}[!] You can use this hash for VirusTotal reputation checks.${COLOR_RESET}"

rm -f "$TMP"
exit 0
