IP ?= 127.0.0.1

OPENSSL_VERSION=1.0.2
IMG_NAME=openssl-client-1-0-2

client: client.Dockerfile client.cpp client.Makefile | openssl-img
	docker build -t ${IMG_NAME} -f $< .
	docker container create --name temp ${IMG_NAME}
	docker container cp temp:/build/client ./
	docker container rm temp

openssl-img: openssl.Dockerfile
	make -C ../ubuntu-latest
	docker build -t openssl:${OPENSSL_VERSION} -f $< .

run: client
	./$< ${IP} ${CHAIN}

fmt:
	clang-format -i client.cpp
