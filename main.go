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
	cert, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return
	}
	config := &tls.Config{Certificates: []tls.Certificate{cert}}
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
		if err != nil {
			log.Printf("failed to send to %s:%v\n", addr, err)
		}
		wg.Done()
	}(srcConn, dstConn)
	go func(srcConn net.Conn, dstConn net.Conn) {
		_, err := io.Copy(srcConn, dstConn)
		if err != nil {
			log.Printf("failed to read from %s: %v\n", addr, err)
		}
		wg.Done()
	}(srcConn, dstConn)

	wg.Wait()
	_ = dstConn.Close()
}
