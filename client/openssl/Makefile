client: client.cpp
	g++ -Wall -o $@ client.cpp -lssl -lcrypto

run: client
	./$<

fmt:
	clang-format -i client.cpp
