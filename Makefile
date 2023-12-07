IP?=127.0.0.1
CHAIN_ABS=$(shell readlink -f $${CHAIN})
ITER ?= 1

run-server-go:
	${MAKE} -C go_server run

run-server-nginx:
	${MAKE} -C nginx_server run

run-client-go:
	IP=${IP} CHAIN=${CHAIN_ABS} ITER=${ITER} ${MAKE} -C client/gotls run

run-client-rs-21:
	IP=${IP} CHAIN=${CHAIN_ABS} ITER=${ITER} ${MAKE} -C client/rustls/0.21.7 run

run-client-rs-22:
	IP=${IP} CHAIN=${CHAIN_ABS} ITER=${ITER} ${MAKE} -C client/rustls/0.22.0 run
