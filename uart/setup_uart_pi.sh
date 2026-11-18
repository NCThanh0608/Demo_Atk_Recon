#!/bin/bash
# Chạy script này TRÊN PI (không phải laptop)
# sudo bash setup_uart_pi.sh

set -e

echo "=== Cài đặt UART Server trên Pi ==="

# 1. Copy service file
cp /home/pi/demo_atk_recon/uart-server.service /etc/systemd/system/uart-server.service

# 2. Enable và start service
systemctl daemon-reload
systemctl enable uart-server.service

echo ""
echo "=== Reboot để áp dụng thay đổi cmdline ==="
echo "Sau reboot, service uart-server sẽ tự chạy."
echo ""
read -p "Reboot ngay? [y/N] " ans
if [[ "$ans" == "y" || "$ans" == "Y" ]]; then
    reboot
fi
