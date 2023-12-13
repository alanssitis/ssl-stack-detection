FROM openssl:3.2.0

WORKDIR /build

COPY client.Makefile ./Makefile
COPY client.cpp ./

RUN make client

