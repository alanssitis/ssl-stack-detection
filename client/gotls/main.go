package main

import (
	"crypto/x509"
	"log"
	"os"

	tls "github.com/refraction-networking/utls"
)

func main() {
    dat, err := os.ReadFile("../../go_server/server.crt")
    if err != nil {
        log.Println(err)
        return
    }

    cert_pool := x509.NewCertPool()
    cert_pool.AppendCertsFromPEM(dat)

    conf := &tls.Config{
        CipherSuites: []uint16{tls.TLS_AES_128_GCM_SHA256},
        RootCAs: cert_pool,
    }

    conn, err := tls.Dial("tcp", "127.0.0.1:443", conf)
    if err != nil {
        log.Fatalln(err)
    }
    defer conn.Close()

    conn.Handshake()
}
