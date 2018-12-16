all:
	c-for-go -nocgo -out ../ ipset.yml
clean:
	rm -f const.go
test:
	go test -v .