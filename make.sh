GOARCH=mipsle GOOS=linux GOMIPS=softfloat go build -ldflags="-s -w" -o vpnerd ./cmd/vpnerd
upx --best vpnerd
