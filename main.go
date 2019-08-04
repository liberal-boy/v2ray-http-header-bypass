package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"v2ray.com/core/transport/internet/headers/http"
)

var methodBuf []byte
var listen, destination, bypass, cert, key string
var authenticator, _ = http.NewHttpAuthenticator(nil, &http.Config{
	Request:  &http.RequestConfig{},
	Response: &http.ResponseConfig{},
})

func main() {
	if !strings.Contains(os.Getenv("GODEBUG"), "tls13") {
		_ = os.Setenv("GODEBUG", os.Getenv("GODEBUG")+",tls13=1")
	}

	var method string

	flag.StringVar(&listen, "l", ":443", "listen address")
	flag.StringVar(&destination, "d", "127.0.0.1:8000", "v2ray server address")
	flag.StringVar(&bypass, "b", "127.0.0.1:80", "bypass server address")
	flag.StringVar(&cert, "cert", "", "path to certificate file, blank to disable TLS")
	flag.StringVar(&key, "key", "", "path to key file, blank to disable TLS")
	flag.StringVar(&method, "method", "V2RAY", "method name of v2ray http header")
	flag.Parse()

	methodBuf = []byte(method)

	server()
}

func listenTls() (ln net.Listener, err error) {
	certs := strings.Split(cert, ",")
	keys := strings.Split(key, ",")
	keyPairs := make([]tls.Certificate, len(certs))
	for i := 0; i < len(keyPairs); i++ {
		keyPairs[i], err = tls.LoadX509KeyPair(certs[i], keys[i])
		if err != nil {
			return
		}
	}

	config := &tls.Config{
		Certificates: keyPairs,
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,

			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		},
	}
	config.BuildNameToCertificate()

	ln, err = tls.Listen("tcp", listen, config)
	return
}

func listenTcp() (ln net.Listener, err error) {
	ln, err = net.Listen("tcp", listen)
	return
}

func server() {
	var ln net.Listener
	var err error

	if cert != "" && key != "" {
		ln, err = listenTls()
	} else {
		ln, err = listenTcp()
	}

	if err != nil {
		log.Fatalf("failed to listen on %s: %v", listen, err)
	}

	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("fail to establish conn: %v\n", err)
			continue
		}
		go handle(conn)
	}
}

func handle(srcConn net.Conn) {
	defer srcConn.Close()

	buf := make([]byte, len(methodBuf)+1)
	_, err := srcConn.Read(buf)
	if err != nil && err != io.EOF {
		log.Printf("fail to read method:%v\n", err)
		return
	}
	isSpecifiedMethod := bytes.Compare(buf[0:len(methodBuf)], methodBuf) == 0 && buf[len(methodBuf)] == ' '

	var addr string
	if isSpecifiedMethod {
		addr = destination
		srcConn = authenticator.Server(srcConn)
	} else {
		addr = bypass
	}

	var dstConn net.Conn
	if strings.HasPrefix(addr, "unix:") {
		dstConn, err = net.Dial("unix", addr[5:])
	} else {
		dstConn, err = net.Dial("tcp", addr)
	}

	if err != nil {
		log.Printf("fail to connect to %s :%v\n", addr, err)
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func(srcConn net.Conn, dstConn net.Conn) {
		if !isSpecifiedMethod {
			_, _ = dstConn.Write(buf)
		}
		_, err := io.Copy(dstConn, srcConn)
		if err != nil && err != io.EOF {
			log.Printf("failed to send to %s:%v\n", addr, err)
		}
		wg.Done()
	}(srcConn, dstConn)
	go func(srcConn net.Conn, dstConn net.Conn) {
		_, err := io.Copy(srcConn, dstConn)
		if err != nil && err != io.EOF {
			log.Printf("failed to read from %s: %v\n", addr, err)
		}
		wg.Done()
	}(srcConn, dstConn)

	wg.Wait()
	_ = dstConn.Close()
}
