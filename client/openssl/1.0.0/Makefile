IP ?= 127.0.0.1

CXXFLAGS+=-Wall -Werror -O3

CPPFLAGS+=-I./openssl/include
LDFLAGS+=-L./openssl
LDLIBS+=-lssl -lcrypto -ldl -lpthread
ENV=env LD_LIBRARY_PATH=../openssl
MEMUSAGE=/usr/bin/time -f %M

client: client.cpp

run: client
	./$< ${IP} ${CHAIN}

fmt:
	clang-format -i client.cpp
