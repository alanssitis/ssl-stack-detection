CXXFLAGS+=-g -Wall -Werror -O3 -static -static-libgcc -static-libstdc++

CPPFLAGS+=-I./openssl/include
LDFLAGS+=-L./openssl
LDLIBS+=-lssl -lcrypto -ldl -lpthread
ENV=env LD_LIBRARY_PATH=../openssl
MEMUSAGE=/usr/bin/time -f %M

client: client.cpp
