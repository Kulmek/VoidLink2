#!/bin/bash
# Wait for server user_data to complete and server to start
# Then poll for server code

set -euo pipefail

SERVER_IP="$1"
SSH_KEY="$2"

echo "Waiting for server user_data to complete (120s)..."
sleep 120

# Poll for server code
for i in {1..30}; do
  SERVER_CODE=$(ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "$SSH_KEY" ubuntu@"$SERVER_IP" "cat /opt/voidlink2/server_code.txt 2>/dev/null || true")
  if [ -n "$SERVER_CODE" ] && [[ "$SERVER_CODE" == TUN-* ]]; then
    echo "server_code=$SERVER_CODE" >> $GITHUB_OUTPUT
    exit 0
  fi
  echo "Waiting for server code... ($i/30)"
  sleep 10
done

echo "::error::Server code not available after 5 minutes"
exit 1