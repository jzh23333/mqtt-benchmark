CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o mqtt-benchmark

scp mqtt-benchmark root@8.213.148.130:/root