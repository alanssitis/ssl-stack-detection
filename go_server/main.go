package main

import (
	"crypto/tls"
	"io"
	"log"
)

func main() {
	log.SetFlags(log.Lshortfile)

	cert, err := tls.LoadX509KeyPair(
		"../certs/go.server.chain",
		"../certs/go.server.key",
	)
	if err != nil {
		log.Println(err)
		return
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	ln, err := tls.Listen("tcp", ":443", config)
	if err != nil {
		log.Fatalf("tls.Listen() failed: %+v\n", err)
	}
	defer ln.Close()

	for {
		netConn, err := ln.Accept()
		if err != nil {
			log.Printf("ln.Accept() failed: %+v\n", err)
			continue
		}
		tlsConn := tls.Server(netConn, config)
		if err := tlsConn.Handshake(); err != nil && err != io.EOF {
			log.Printf("tls_conn.Handshake() failed: %+v\n", err)
		}

		tlsConn.Close()
		netConn.Close()
	}
}
