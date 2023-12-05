package main

import (
	"log"

    tls "github.com/refraction-networking/utls"
)

func main() {
    conf := &tls.Config{
        Certificates: []tls.Certificate{},
        CipherSuites: []uint16{tls.TLS_AES_128_GCM_SHA256},
    }

    conn, err := tls.Dial("tcp", "172.20.0.1:4443", conf)
    if err != nil {
        log.Fatalln(err)
    }
    defer conn.Close()

    conn.Handshake()
}
