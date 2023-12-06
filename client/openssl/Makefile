client: client.cpp
	g++ -Wall -g -o $@ client.cpp -lssl -lcrypto

run: client
	./$< ${IP} ${CHAIN}

fmt:
	clang-format -i client.cpp
