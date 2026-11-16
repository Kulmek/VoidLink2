#!/bin/bash
# Generate Ansible inventory from Terraform outputs and server code

set -euo pipefail

SERVER_IP="$1"
CLIENT_A_IP="$2"
CLIENT_B_IP="$3"
CLIENT_C_IP="$4"
SERVER_CODE="$5"
WIN_PASSWORD="$6"

cat > infrastructure/ansible/inventory.yml <<EOF
all:
  children:
    server:
      hosts:
        voidlink2-server:
          ansible_host: $SERVER_IP
          ansible_user: ubuntu
          ansible_ssh_private_key_file: ~/.ssh/id_rsa
          ansible_become: yes
          server_code: "$SERVER_CODE"
    clients:
      hosts:
        voidlink2-client-a:
          ansible_host: $CLIENT_A_IP
          ansible_user: Administrator
          ansible_password: "$WIN_PASSWORD"
          ansible_connection: winrm
          ansible_winrm_transport: basic
          ansible_winrm_server_cert_validation: ignore
          ansible_port: 5985
        voidlink2-client-b:
          ansible_host: $CLIENT_B_IP
          ansible_user: Administrator
          ansible_password: "$WIN_PASSWORD"
          ansible_connection: winrm
          ansible_winrm_transport: basic
          ansible_winrm_server_cert_validation: ignore
          ansible_port: 5985
        voidlink2-client-c:
          ansible_host: $CLIENT_C_IP
          ansible_user: Administrator
          ansible_password: "$WIN_PASSWORD"
          ansible_connection: winrm
          ansible_winrm_transport: basic
          ansible_winrm_server_cert_validation: ignore
          ansible_port: 5985
  vars:
    windows_admin_password: "$WIN_PASSWORD"
EOF

echo "Inventory generated at infrastructure/ansible/inventory.yml"