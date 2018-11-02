VERSION=0.4.0

default:
	go build

clean:
	rm -f cloud-gate.*


sign: clean all
	gpg -a --detach-sign cloud-gate.Linux
	gpg -a --detach-sign cloud-gate.Darwin
	gpg -a --detach-sign cloud-gate.win64

all: linux darwin windows

linux:
	env GOOS=linux GOARCH=amd64 go build -ldflags "-X main.Version=${VERSION}" -o cloud-gate.Linux

darwin:
	env GOOS=darwin GOARCH=amd64 go build -ldflags "-X main.Version=${VERSION}" -o cloud-gate.Darwin

windows:
	env GOOS=windows GOARCH=amd64 go build -ldflags "-X main.Version=${VERSION}" -o cloud-gate.win64
