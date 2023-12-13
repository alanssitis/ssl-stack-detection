FROM openssl:1.1.1

WORKDIR /build

COPY client.Makefile ./Makefile
COPY client.cpp ./

RUN make client

