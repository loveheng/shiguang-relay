#!/usr/bin/env sh
# 灾备快照（fact §7.1-3）：pg_dump | gzip 落盘 + 保留天数轮转；配了 RCLONE_REMOTE 即异地同步。
# 容器内执行（backup sidecar）；宿主想手动跑：
#   podman-compose -f docker-compose.prod.yml exec -T backup /backup.sh
set -eu

: "${PG_DB:=relay}"
: "${PG_USER:=relay}"
: "${BACKUP_DIR:=/backups}"
: "${BACKUP_RETAIN_DAYS:=7}"

TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${BACKUP_DIR}/${PG_DB}-${TS}.sql.gz"

mkdir -p "$BACKUP_DIR"
# 纯数据快照（不含角色/表空间），还原时目标库需已建好
pg_dump -h "${PGHOST:-postgres}" -U "$PG_USER" -d "$PG_DB" --no-owner --no-acl | gzip -9 > "$OUT"

echo "[$(date -u +%FT%TZ)] snapshot written: $OUT ($(wc -c < "$OUT") bytes)"

# 本地轮转
find "$BACKUP_DIR" -type f -name "${PG_DB}-*.sql.gz" -mtime "+${BACKUP_RETAIN_DAYS}" -delete

# 异地同步（可选）：容器需安装 rclone 并配置好远端；未配置即跳过，不阻断本地备份
if [ -n "${RCLONE_REMOTE:-}" ] && command -v rclone >/dev/null 2>&1; then
  rclone copy "$OUT" "$RCLONE_REMOTE" && echo "[$(date -u +%FT%TZ)] uploaded to $RCLONE_REMOTE"
else
  echo "[$(date -u +%FT%TZ)] RCLONE_REMOTE 未配置或缺 rclone：仅本地留存（请务必把 $BACKUP_DIR 挂到异地盘）"
fi
