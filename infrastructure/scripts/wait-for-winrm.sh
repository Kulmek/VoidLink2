#!/bin/bash
# Wait for WinRM to be ready on Windows clients

set -euo pipefail

CLIENT_A_IP="$1"
CLIENT_B_IP="$2"
CLIENT_C_IP="$3"

for ip in "$CLIENT_A_IP" "$CLIENT_B_IP" "$CLIENT_C_IP"; do
  echo "Waiting for WinRM on $ip..."
  for i in {1..60}; do
    if nc -z -w 5 "$ip" 5985 2>/dev/null; then
      echo "WinRM ready on $ip"
      break
    fi
    sleep 10
  done
done