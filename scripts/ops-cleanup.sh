#!/usr/bin/env bash
# 运维收尾（Phase 1.8）：瞬时信令 TTL 清理 + 磁盘水位告警。
# 建议宿主 cron：*/30 * * * * /path/to/shiguang-relay/scripts/ops-cleanup.sh >> /var/log/relay-ops.log 2>&1
set -euo pipefail

COMPOSE="${COMPOSE:-podman-compose -f docker-compose.prod.yml}"
DISK_LIMIT_PCT="${DISK_LIMIT_PCT:-85}"
PG_SERVICE="${PG_SERVICE:-postgres}"

echo "[$(date -u +%FT%TZ)] 清理过期/已消费的瞬时信令（TTL 即焚）"
$COMPOSE exec -T "$PG_SERVICE" psql -U "${PG_USER:-relay}" -d "${PG_DB:-relay}" -v ON_ERROR_STOP=1 -c \
  "DELETE FROM relay_messages WHERE status = 'acked' OR expires_at < now();"

echo "[$(date -u +%FT%TZ)] 磁盘水位检查（阈值 ${DISK_LIMIT_PCT}%）"
usage="$(df -P / | awk 'NR==2 {gsub("%","",$5); print $5}')"
if [ "$usage" -ge "$DISK_LIMIT_PCT" ]; then
  echo "ALERT: 磁盘水位 ${usage}% ≥ ${DISK_LIMIT_PCT}% —— 检查 PG 数据卷与备份卷"
  exit 1
fi
echo "OK: 磁盘水位 ${usage}%"
