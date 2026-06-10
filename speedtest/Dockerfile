# mmwx-speedtester 容器镜像。
#
# 用法:
#   docker run -d --name mmwx-speedtester --restart unless-stopped \
#     -e MMWX_MASTER=https://your-master.example.com \
#     -e MMWX_SPEEDTEST_TOKEN=<token> \
#     -e MMWX_SPEEDTEST_NAME=home-tester \
#     -v mmwx-speedtester-data:/data \
#     ghcr.io/iluobei/mmwx-speedtester:latest
#
# 持久 volume /data 用于缓存 mihomo 二进制(避免每次重启都重新从 GitHub Release 下载)。
# 必须能出网访问:主控 WS、GitHub Release(拉 mihomo)、测速目标(Cloudflare 等)。

# ---- builder ----
FROM golang:1.26-alpine AS builder
WORKDIR /src
# 单独 cp go.mod/sum 让 mod download 缓存层稳定
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# -trimpath + -s -w 缩小 binary;CGO_ENABLED=0 全静态
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/mmwx-speedtester .

# ---- runtime ----
FROM alpine:3.20
# ca-certificates:HTTPS 拉 mihomo + 主控 wss 鉴权
# tzdata:日志时间戳本地化(可选)
RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S speedtest && adduser -S -G speedtest speedtest && \
    mkdir -p /data && chown speedtest:speedtest /data

COPY --from=builder /out/mmwx-speedtester /usr/local/bin/mmwx-speedtester

USER speedtest
WORKDIR /data
VOLUME ["/data"]

# 不写默认 ENV(强制运行时显式传入,避免空 token 起容器后无限报错)
ENTRYPOINT ["/usr/local/bin/mmwx-speedtester"]
