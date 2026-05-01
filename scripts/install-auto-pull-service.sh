#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVICE_DIR="${HOME}/.config/systemd/user"
SERVICE_FILE="${SERVICE_DIR}/haven-backend-auto-pull.service"
TIMER_FILE="${SERVICE_DIR}/haven-backend-auto-pull.timer"

mkdir -p "$SERVICE_DIR"

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Auto pull and deploy Haven backend

[Service]
Type=oneshot
Environment=HAVEN_BACKEND_REPO=${REPO_DIR}
ExecStart=${REPO_DIR}/scripts/auto-pull-deploy.sh
EOF

cat > "$TIMER_FILE" <<'EOF'
[Unit]
Description=Poll GitHub for Haven backend updates

[Timer]
OnBootSec=30s
OnUnitActiveSec=60s
AccuracySec=10s
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl --user daemon-reload
systemctl --user enable --now haven-backend-auto-pull.timer
systemctl --user list-timers haven-backend-auto-pull.timer
