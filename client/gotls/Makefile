IP ?= 127.0.0.1
ITER ?= 1
ifndef CHAIN
$(error CHAIN not defined)
endif

goclient: main.go
	go build -o goclient

run: goclient
	./$< ${IP} ${CHAIN} ${ITER}
