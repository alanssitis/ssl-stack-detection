FROM build-base-latest

WORKDIR /build

RUN git clone https://github.com/openssl/openssl.git -b OpenSSL_1_1_1
RUN cd openssl; ./config; make; make install

