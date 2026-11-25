#!/usr/bin/env bash
# Deploy CamFleetManager to Raspberry Pi
# Usage: ./deploy.sh [PI_HOST] [PI_USER]
#   default: pi@192.168.1.197

set -e

PI_HOST="${1:-192.168.1.197}"
PI_USER="${2:-pi}"
REMOTE_DIR="/home/${PI_USER}/CamFleetManager"
SERVICE_NAME="camfleet"
PORT=8088

echo "=== Deploying CamFleetManager to ${PI_USER}@${PI_HOST} ==="

# 1. Create remote directory
echo "[1/5] Creating remote directory..."
ssh "${PI_USER}@${PI_HOST}" "mkdir -p ${REMOTE_DIR}/{backend,frontend/assets/{css,js},data,binaries,logs}"

# 2. Copy files
echo "[2/5] Copying files..."
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

scp "${SCRIPT_DIR}/backend/server.py"               "${PI_USER}@${PI_HOST}:${REMOTE_DIR}/backend/"
scp "${SCRIPT_DIR}/requirements.txt"                 "${PI_USER}@${PI_HOST}:${REMOTE_DIR}/"
scp "${SCRIPT_DIR}/data/credentials.csv"             "${PI_USER}@${PI_HOST}:${REMOTE_DIR}/data/"
scp "${SCRIPT_DIR}/frontend/index.html"              "${PI_USER}@${PI_HOST}:${REMOTE_DIR}/frontend/"
scp "${SCRIPT_DIR}/frontend/assets/css/styles.css"   "${PI_USER}@${PI_HOST}:${REMOTE_DIR}/frontend/assets/css/"
scp "${SCRIPT_DIR}/frontend/assets/js/config.js"     "${PI_USER}@${PI_HOST}:${REMOTE_DIR}/frontend/assets/js/"
scp "${SCRIPT_DIR}/frontend/assets/js/api.js"        "${PI_USER}@${PI_HOST}:${REMOTE_DIR}/frontend/assets/js/"
scp "${SCRIPT_DIR}/frontend/assets/js/ui.js"         "${PI_USER}@${PI_HOST}:${REMOTE_DIR}/frontend/assets/js/"
scp "${SCRIPT_DIR}/frontend/assets/js/app.js"        "${PI_USER}@${PI_HOST}:${REMOTE_DIR}/frontend/assets/js/"

# Copy binaries if they exist locally
if ls "${SCRIPT_DIR}/binaries/"* 1>/dev/null 2>&1; then
  echo "    Copying binaries..."
  scp "${SCRIPT_DIR}/binaries/"* "${PI_USER}@${PI_HOST}:${REMOTE_DIR}/binaries/" 2>/dev/null || true
fi

# 3. Install dependencies
echo "[3/5] Installing Python dependencies..."
ssh "${PI_USER}@${PI_HOST}" "cd ${REMOTE_DIR} && pip3 install --user -r requirements.txt"

# 4. Create systemd service
echo "[4/5] Setting up systemd service..."
ssh "${PI_USER}@${PI_HOST}" "sudo tee /etc/systemd/system/${SERVICE_NAME}.service > /dev/null" <<EOF
[Unit]
Description=Camera Fleet Manager
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 ${REMOTE_DIR}/backend/server.py
WorkingDirectory=${REMOTE_DIR}
User=${PI_USER}
Restart=always
RestartSec=3
Environment=CAMFLEET_PORT=8088
Environment=CAMFLEET_FILE_PORT=9999
AmbientCapabilities=CAP_NET_RAW

[Install]
WantedBy=multi-user.target
EOF

# 5. Enable and restart service
echo "[5/5] Starting service..."
ssh "${PI_USER}@${PI_HOST}" "sudo systemctl daemon-reload && sudo systemctl enable ${SERVICE_NAME} && sudo systemctl restart ${SERVICE_NAME}"

echo ""
echo "=== Done! ==="
echo "Web UI:     http://${PI_HOST}:${PORT}"
echo "File server: http://${PI_HOST}:9999"
echo ""
echo "Commands:"
echo "  Status:  ssh ${PI_USER}@${PI_HOST} 'systemctl status ${SERVICE_NAME}'"
echo "  Logs:    ssh ${PI_USER}@${PI_HOST} 'journalctl -u ${SERVICE_NAME} -f'"
echo "  Restart: ssh ${PI_USER}@${PI_HOST} 'sudo systemctl restart ${SERVICE_NAME}'"
