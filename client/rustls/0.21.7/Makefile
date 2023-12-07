IP ?= 127.0.0.1
ITER ?= 1
ifndef CHAIN
$(error CHAIN not defined)
endif

target/release/rustls: src/main.rs
	cargo build --release

run: target/release/rustls
	$< ${IP} ${CHAIN} ${ITER}

