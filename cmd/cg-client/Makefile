VERSION=0.4.2
ifeq ($(DEFAULT_BASE_URL),)
#TEST := $(something else)
DEFAULT_BASE_URL:="https://cloud-gate.example.net"
endif

default:
	go build

clean:
	rm -f cloud-gate.*


sign: clean all
	gpg -a --detach-sign cloud-gate.Linux
	gpg -a --detach-sign cloud-gate.Darwin
	gpg -a --detach-sign cloud-gate.win64.exe

all: linux darwin windows

linux:
	env GOOS=linux GOARCH=amd64 go build -ldflags "-X main.Version=${VERSION} -X main.DefaultBaseURL=${DEFAULT_BASE_URL}" -o cloud-gate.Linux

darwin:
	env GOOS=darwin GOARCH=amd64 go build -ldflags "-X main.Version=${VERSION} -X main.DefaultBaseURL=${DEFAULT_BASE_URL}" -o cloud-gate.Darwin

windows:
	env GOOS=windows GOARCH=amd64 go build -ldflags "-X main.Version=${VERSION} -X main.DefaultBaseURL=${DEFAULT_BASE_URL}" -o cloud-gate.win64.exe
