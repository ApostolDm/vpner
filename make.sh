GOARCH=mipsle GOOS=linux GOMIPS=softfloat go build -ldflags="-s -w" -o vpner main.go
upx --best vpner
