GOPATH ?= ${shell go env GOPATH}


# This is how we want to name the binary output
BINARY=cloud-gate
#
# # These are the values we want to pass for Version and BuildTime
VERSION=0.7.7

all:
	@cd $(GOPATH)/src; go install github.com/Symantec/cloud-gate/cmd/*


get-deps:
	go get -t ./...

clean:
	rm -f bin/*
	rm -f cloud-gate-*.tar.gz

${BINARY}-${VERSION}.tar.gz:
	mkdir ${BINARY}-${VERSION}
	rsync -av --exclude="config.yml" --exclude="*.pem" --exclude="*.out" lib/ ${BINARY}-${VERSION}/lib/
	rsync -av --exclude="config.yml" --exclude="*.pem" --exclude="*.out" --exclude="*.key" cmd/ ${BINARY}-${VERSION}/cmd/
	rsync -av  misc/ ${BINARY}-${VERSION}/misc/
	cp LICENSE Makefile cloud-gate.spec README.md ${BINARY}-${VERSION}/
	tar -cvzf ${BINARY}-${VERSION}.tar.gz ${BINARY}-${VERSION}/
	rm -rf ${BINARY}-${VERSION}/

rpm:    ${BINARY}-${VERSION}.tar.gz
	rpmbuild -ta ${BINARY}-${VERSION}.tar.gz

tar:    ${BINARY}-${VERSION}.tar.gz


format:
	gofmt -s -w .

format-imports:
	goimports -w .


test:
	@find * -name '*_test.go' |\
	sed -e 's@^@github.com/Symantec/cloud-gate/@' -e 's@/[^/]*$$@@' |\
	sort -u | xargs go test
