all:
	@cd $(GOPATH)/src; go install github.com/Symantec/cloud-gate/cmd/*


format:
	gofmt -s -w .

format-imports:
	goimports -w .


test:
	@find * -name '*_test.go' |\
	sed -e 's@^@github.com/Symantec/cloud-gate/@' -e 's@/[^/]*$$@@' |\
	sort -u | xargs go test
