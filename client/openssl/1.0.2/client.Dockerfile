FROM openssl:1.0.2

WORKDIR /build

COPY client.Makefile ./Makefile
COPY client.cpp ./

RUN make client

