FROM build-base-latest

WORKDIR /build

RUN git clone https://github.com/openssl/openssl.git -b openssl-3.1.1
RUN cd openssl; ./Configure; make; make install

