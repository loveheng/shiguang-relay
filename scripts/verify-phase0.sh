#!/usr/bin/env bash
# Phase 0 退出验收：起 PG → 应用 schema.sql → 插一条合法事件并验证 UNIQUE(bundle_id, seq_id) 生效
# 前置：docker compose 可用（本机为 podman 的 docker CLI 亦可）
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo ">> 起 PG/Redis"
docker compose up -d postgres redis

echo ">> 等待 PG 就绪"
for i in $(seq 1 40); do
  if docker compose exec -T postgres pg_isready -U relay -d relay >/dev/null 2>&1; then break; fi
  sleep 1
done

echo ">> 重建 public schema（本地联调库，可重复执行）"
docker compose exec -T postgres psql -U relay -d relay -v ON_ERROR_STOP=1 -c \
  "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"

echo ">> 应用 DDL（schema.sql）"
docker compose exec -T postgres psql -U relay -d relay -v ON_ERROR_STOP=1 -f - < "$ROOT/schema.sql"
docker compose exec -T postgres psql -U relay -d relay -tAc \
  "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY 1"

echo ">> 退出条件：插入一条合法事件 + 同 (bundle_id, seq_id) 重复插入应失败"
docker compose exec -T postgres psql -U relay -d relay -v ON_ERROR_STOP=1 <<'SQL'
INSERT INTO users (identity_key_pub, signed_prekey_pub, signed_prekey_sig) VALUES ('\x01','\x02','\x03');
INSERT INTO bundles (initiator_id, proposal_type, participant_uids, expires_at)
  SELECT user_id, 'CONSENSUS', ARRAY[user_id], now() + interval '7 days' FROM users LIMIT 1;
INSERT INTO team_schedule_events (bundle_id, seq_id, action_type, sender_user_id, cipher, client_msg_id)
  SELECT bundle_id, 1, 'ATTACH_FACT', initiator_id, '\xdeadbeef', 'msg-1' FROM bundles LIMIT 1;
SQL

set +e
docker compose exec -T postgres psql -U relay -d relay -v ON_ERROR_STOP=1 <<'SQL'
INSERT INTO team_schedule_events (bundle_id, seq_id, action_type, sender_user_id, cipher, client_msg_id)
  SELECT bundle_id, 1, 'ATTACH_FACT', initiator_id, '\xdeadbeef', 'msg-2' FROM bundles LIMIT 1;
SQL
DUP_RC=$?
set -e

if [[ $DUP_RC -eq 0 ]]; then
  echo "FAIL：重复 (bundle_id, seq_id) 竟然插入成功 —— UNIQUE 约束未生效"
  exit 1
fi
echo "OK：seq 唯一约束生效，Phase 0 退出条件达成"

echo ">> 清理测试数据（保留表结构）"
docker compose exec -T postgres psql -U relay -d relay -v ON_ERROR_STOP=1 -c \
  "TRUNCATE team_schedule_events, bundles, users CASCADE"
