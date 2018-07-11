default:
	go build

clean:
	rm -f cloud-gate.*


all: linux darwin

linux:
	env GOOS=linux GOARCH=amd64 go build -o cloud-gate.Linux

darwin:
	env GOOS=darwin GOARCH=amd64 go build -o cloud-gate.Darwin
