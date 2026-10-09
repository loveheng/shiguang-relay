# shiguang-relay · 盲中继服务端镜像
# Phase 0 只交付骨架；Phase 1 落地 cmd/relayd 后本文件即可直接 build。
FROM golang:1.23-alpine AS build

WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/relayd ./cmd/relayd

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=build /out/relayd /app/relayd
# 只读根卷运行：服务端无任何本地状态（状态全在 PG/Redis）
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/app/relayd"]
