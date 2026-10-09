#!/usr/bin/env bash
# Phase 1.1 冒烟：真实 PG/Redis + 真实 relayd 进程，验证鉴权闭环与幂等去重
# 前置：compose 可用（默认 podman-compose）、Go 工具链在 PATH
set -euo pipefail

COMPOSE="${COMPOSE:-podman-compose}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export PATH="${HOME}/sdk/go1.23.6/bin:${HOME}/sdk/protoc/bin:${HOME}/go/bin:${PATH}"

echo ">> 起 PG/Redis（$COMPOSE）"
"$COMPOSE" up -d postgres redis
for i in $(seq 1 40); do
  if "$COMPOSE" exec -T postgres pg_isready -U relay -d relay >/dev/null 2>&1; then break; fi
  sleep 1
done

echo ">> 确认 users 表存在（缺失则应用 schema.sql）"
HAS_USERS="$("$COMPOSE" exec -T postgres psql -U relay -d relay -tAc \
  "SELECT to_regclass('public.users') IS NOT NULL")"
if [[ "$HAS_USERS" != "t" ]]; then
  "$COMPOSE" exec -T postgres psql -U relay -d relay -v ON_ERROR_STOP=1 -f - < "$ROOT/schema.sql"
fi

echo ">> 构建 relayd"
mkdir -p "$ROOT/bin"
go build -o "$ROOT/bin/relayd" ./cmd/relayd

RELAY_JWT_SECRET="local-smoke-secret-local-smoke-secret" \
RELAY_POW_DIFFICULTY=0 \
RELAY_LISTEN=":8080" \
RELAY_PG_DSN="postgres://relay:relay@localhost:5432/relay?sslmode=disable" \
RELAY_REDIS_ADDR="localhost:6379" \
  "$ROOT/bin/relayd" > "$ROOT/bin/relayd.log" 2>&1 &
PID=$!
trap 'kill "$PID" 2>/dev/null || true' EXIT

for i in $(seq 1 40); do
  if curl -fsS "http://localhost:8080/v1/healthz" >/dev/null 2>&1; then break; fi
  sleep 0.5
done

NOW="$(date +%s)"
post() { # post <path> <json> <msg_id> [token]
  local path="$1" body="$2" msg="$3" token="${4:-}"
  local auth=()
  [[ -n "$token" ]] && auth=(-H "Authorization: Bearer $token")
  curl -sS -o /tmp/resp.json -w '%{http_code}' -X POST "http://localhost:8080$path" \
    -H "Content-Type: application/json" \
    -H "X-Client-Msg-Id: $msg" -H "X-Client-Ts: $NOW" \
    "${auth[@]}" -d "$body"
}
assert() { # assert <期望码> <实际码> <说明>
  if [[ "$2" != "$1" ]]; then
    echo "FAIL: $3 —— 期望 $1，实际 $2；响应: $(cat /tmp/resp.json)"
    exit 1
  fi
  echo "OK: $3 ($2)"
}

CODE=$(curl -sS -o /tmp/resp.json -w '%{http_code}' http://localhost:8080/v1/healthz)
assert 200 "$CODE" "healthz"

CODE=$(post /v1/schedule/action '{}' smoke-1)
assert 401 "$CODE" "无 token 访问受保护路由"

CODE=$(post /v1/schedule/action '{}' smoke-2)
assert 401 "$CODE" "（对照）无 token 再次访问"

CODE=$(curl -sS -o /tmp/resp.json -w '%{http_code}' -X POST http://localhost:8080/v1/auth/challenge \
  -H "Content-Type: application/json" -d '{"user_id":"nobody"}')
assert 400 "$CODE" "缺 client_msg_id 被拒"

CODE=$(post /v1/auth/challenge '{"user_id":"00000000-0000-0000-0000-000000000000"}' smoke-challenge)
assert 200 "$CODE" "签发 challenge"
NONCE="$(python3 -c "import json;print(json.load(open('/tmp/resp.json'))['nonce'])")"

CODE=$(post /v1/auth/login \
  "{\"user_id\":\"00000000-0000-0000-0000-000000000000\",\"nonce\":\"$NONCE\",\"signed_pop\":\"\",\"pow_solution\":\"\"}" \
  smoke-login)
assert 401 "$CODE" "未注册用户/空签名登录被拒"

CODE=$(post /v1/auth/challenge '{"user_id":"00000000-0000-0000-0000-000000000000"}' smoke-replay)
assert 200 "$CODE" "幂等首次请求"
BODY1="$(cat /tmp/resp.json)"
HEAD1="$(curl -sS -D - -o /tmp/resp.json -X POST http://localhost:8080/v1/auth/challenge \
  -H "Content-Type: application/json" -H "X-Client-Msg-Id: smoke-replay" -H "X-Client-Ts: $NOW" \
  -d '{"user_id":"00000000-0000-0000-0000-000000000000"}')"
BODY2="$(cat /tmp/resp.json)"
if ! grep -qi "x-idempotent-replay: 1" <<<"$HEAD1"; then
  echo "FAIL: 重放未带 X-Idempotent-Replay 头"
  exit 1
fi
if [[ "$BODY1" != "$BODY2" ]]; then
  echo "FAIL: 重放响应体与首次不一致"
  exit 1
fi
echo "OK: 重放同 client_msg_id 幂等返回（响应体一致）"

echo ">> 集成测试（真 PG：注册 PoP / OPK 原子弹出 / 补仓 / 好友 Ticket 建联 / 协同动作并发取号 / 发现同步与金库）"
RELAY_TEST_PG_DSN="postgres://relay:relay@localhost:5432/relay?sslmode=disable" \
  go test ./... -count=1

echo ">> relayd 日志尾部："
tail -3 "$ROOT/bin/relayd.log" || true
echo "Phase 1 冒烟全通（1.1 鉴权 + 1.2 注册/OPK + 1.3 好友域 + 1.4 协同动作 + 1.5 发现与同步）"
