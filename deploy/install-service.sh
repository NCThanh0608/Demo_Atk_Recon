#!/usr/bin/env bash
# Cài Red Team Ops Console thành systemd service trên Raspberry Pi.
# Chạy TRÊN Pi, trong thư mục deploy/:  bash install-service.sh
set -euo pipefail

UNIT="redteam-console.service"
HERE="$(cd "$(dirname "$0")" && pwd)"

echo "[*] Dừng server tạm (nohup) nếu có..."
pkill -f "http.server 8080" 2>/dev/null || true

echo "[*] Cài unit vào /etc/systemd/system/ ..."
sudo cp "$HERE/$UNIT" "/etc/systemd/system/$UNIT"
sudo systemctl daemon-reload

echo "[*] Bật khi khởi động + chạy ngay..."
sudo systemctl enable --now "$UNIT"

echo "[*] Trạng thái:"
systemctl --no-pager --full status "$UNIT" || true

echo "[*] Kiểm tra cổng 8080:"
ss -ltn | grep ':8080' || echo "  (chưa thấy listener — xem: journalctl -u $UNIT -e)"

echo "[✓] Xong. Truy cập: http://10.42.0.1:8080"
