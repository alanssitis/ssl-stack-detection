package main

import (
	"crypto/tls"
	"io"
	"log"
)

func prependRecordHeader(hello []byte, minTLSVersion uint16) []byte {
	l := len(hello)
	if minTLSVersion == 0 {
		minTLSVersion = tls.VersionTLS10
	}
	header := []byte{
		uint8(22),
		uint8(minTLSVersion >> 8 & 0xff), uint8(minTLSVersion & 0xff),
		uint8(l >> 8 & 0xff), uint8(l & 0xff),
	}
	return append(header, hello...)
}

func main() {
	log.SetFlags(log.Lshortfile)

	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
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
		} else {
			log.Println("Successful handshake")
		}

		tlsConn.Close()
		netConn.Close()
	}
}
