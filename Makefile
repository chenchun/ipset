all:
	c-for-go -nocgo -out ../ ipset.yml
clean:
	rm -f const.go
test:
	GO111MODULE=on go test -v .
