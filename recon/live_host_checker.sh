#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

COMMON_PORTS=(21 22 23 25 53 80 110 111 135 139 143 443 445 993 995 1723 3306 3389 5900 8080 8443)

if [ ! -f "hosts.txt" ]; then
    echo -e "${RED}[!] hosts.txt file not found!${NC}"
    echo -e "${YELLOW}[*] Please create hosts.txt with one target per line (IP or domain).${NC}"
    exit 1
fi

TOTAL_HOSTS=$(wc -l < hosts.txt)
echo -e "${WHITE}[*] Total targets: $TOTAL_HOSTS${NC}"
echo ""

COUNT=1
LIVE_HOSTS=0

while read HOST; do
    if [ -z "$HOST" ]; then
        continue
    fi
    
    echo -e "${YELLOW}[$COUNT/$TOTAL_HOSTS] Checking: ${WHITE}$HOST${NC}"
    
    IP=$(dig +short $HOST | head -n 1)
    if [ -z "$IP" ]; then
        IP=$(host $HOST 2>/dev/null | grep "has address" | head -n 1 | awk '{print $NF}')
    fi
    if [ -z "$IP" ]; then
        IP="Unable to resolve"
    fi
    echo -e "   ├─ IP Address:   ${CYAN}$IP${NC}"
    
    ping -c 2 -W 2 $HOST > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        PING_STATUS="${GREEN}UP${NC}"
    else
        PING_STATUS="${RED}DOWN${NC}"
    fi
    
    timeout 3 curl -s -k -I "https://$HOST" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        HTTPS_STATUS="${GREEN}OPEN${NC}"
    else
        HTTPS_STATUS="${RED}CLOSED${NC}"
    fi
    
    timeout 3 curl -s -I "http://$HOST" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        HTTP_STATUS="${GREEN}OPEN${NC}"
    else
        HTTP_STATUS="${RED}CLOSED${NC}"
    fi
    
    OPEN_PORTS=""
    for PORT in "${COMMON_PORTS[@]}"; do
        timeout 1 nc -zv -w 1 $HOST $PORT 2>/dev/null
        if [ $? -eq 0 ]; then
            OPEN_PORTS="$OPEN_PORTS $PORT"
        fi
    done
    
    echo -e "   ├─ ICMP Ping:    $PING_STATUS"
    echo -e "   ├─ HTTP (80):    $HTTP_STATUS"
    echo -e "   ├─ HTTPS (443):  $HTTPS_STATUS"
    
    if [ ! -z "$OPEN_PORTS" ]; then
        echo -e "   └─ Open Ports:   ${GREEN}$OPEN_PORTS${NC}"
    else
        echo -e "   └─ Open Ports:   ${RED}None${NC}"
    fi
    
    if [[ $PING_STATUS == *"UP"* ]] || [[ $HTTP_STATUS == *"OPEN"* ]] || [[ $HTTPS_STATUS == *"OPEN"* ]]; then
        LIVE_HOSTS=$((LIVE_HOSTS + 1))
    fi
    
    echo ""
    COUNT=$((COUNT + 1))
    
    sleep 0.5
    
done < hosts.txt

echo -e "${CYAN}══════════════════════════════════════════════════════════${NC}"
echo -e "${WHITE}Scan completed!${NC}"
echo -e "  ${GREEN}Live/Web Open: $LIVE_HOSTS hosts${NC}"
echo -e "  ${RED}Down: $((TOTAL_HOSTS - LIVE_HOSTS)) hosts${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════════${NC}"
