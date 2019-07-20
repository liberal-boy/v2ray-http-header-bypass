package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"io"
	"log"
	"net"
)

var method = []byte("V2RAY")
var listen, destination, bypass, cert, key string

func main() {
	flag.StringVar(&listen, "l", ":443", "listen address")
	flag.StringVar(&destination, "d", "127.0.0.1:8000", "v2ray server address")
	flag.StringVar(&bypass, "b", "127.0.0.1:80", "bypass server address")
	flag.StringVar(&cert, "cert", "", "path to certificate file, blank to disable TLS")
	flag.StringVar(&key, "key", "", "path to key file, blank to disable TLS")
	flag.Parse()
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

	buf := make([]byte, len(method))
	_, err := srcConn.Read(buf)
	if err != nil {
		log.Printf("fail to read method:%v\n", err)
		return
	}

	var addr string
	if bytes.Compare(buf, method) == 0 {
		addr = destination
	} else {
		addr = bypass
	}

	dstConn, err := net.Dial("tcp", addr)
	if err != nil {
		log.Printf("fail to connect to %s :%v\n", addr, err)
		return
	}
	exitChan := make(chan struct{})
	go func(sconn net.Conn, dconn net.Conn, Exit chan<- struct{}) {
		_, _ = dconn.Write(buf)
		_, err := io.Copy(dconn, sconn)
		if err != nil {
			log.Printf("failed to send to %s:%v\n", addr, err)
		}
		exitChan <- struct{}{}
	}(srcConn, dstConn, exitChan)
	go func(sconn net.Conn, dconn net.Conn, Exit chan<- struct{}) {
		_, err := io.Copy(sconn, dconn)
		if err != nil {
			log.Printf("failed to read from %s: %v\n", addr, err)
		}
		exitChan <- struct{}{}
	}(srcConn, dstConn, exitChan)
	<-exitChan
	_ = dstConn.Close()
}
