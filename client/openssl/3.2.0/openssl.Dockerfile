FROM build-base-latest

WORKDIR /build

RUN git clone https://github.com/openssl/openssl.git -b openssl-3.2.0
RUN cd openssl; ./Configure; make; make install

