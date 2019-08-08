package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"v2ray.com/core/transport/internet/headers/http"
)

var config struct {
	Listen       string        `json:"listen"`
	Certificates []certificate `json:"certificates"`
	BypassAddr   string        `json:"bypassAddr"`
	MethodLen    int           `json:"methodLen"`
	MethodAddrs  []*methodAddr `json:"methodsAddrs"`
}

type certificate struct {
	CertificateFile string `json:"certificateFile"`
	KeyFile         string `json:"keyFile"`
}

type methodAddr struct {
	MethodName string `json:"methodName"`
	MethodBuf  []byte `json:"_"`
	Addr       string `json:"addr"`
}

var authenticator, _ = http.NewHttpAuthenticator(nil, &http.Config{
	Response: &http.ResponseConfig{
		Version: &http.Version{Value: ""},
		Status:  &http.Status{Code: "", Reason: ""},
		Header:  []*http.Header{{Name: "Date", Value: []string{""}}},
	},
})

func main() {
	if !strings.Contains(os.Getenv("GODEBUG"), "tls13") {
		_ = os.Setenv("GODEBUG", os.Getenv("GODEBUG")+",tls13=1")
	}

	var method, destination, cert, key, configPath string

	flag.StringVar(&config.Listen, "l", ":443", "listen address")
	flag.StringVar(&destination, "d", "127.0.0.1:8000", "v2ray server address")
	flag.StringVar(&config.BypassAddr, "b", "127.0.0.1:80", "bypass server address")
	flag.StringVar(&cert, "cert", "", "path to certificate file, blank to disable TLS")
	flag.StringVar(&key, "key", "", "path to key file, blank to disable TLS")
	flag.StringVar(&method, "method", "V2RAY", "method name of v2ray http header")
	flag.StringVar(&configPath, "config", "", "path to config file")
	flag.Parse()

	if configPath == "" {
		config.MethodLen = len(method)
		config.MethodAddrs = []*methodAddr{{
			MethodName: method,
			Addr:       destination,
		}}
		if cert != "" && key != "" {
			certs := strings.Split(cert, ",")
			keys := strings.Split(key, ",")
			config.Certificates = make([]certificate, len(certs))
			for i := 0; i < len(config.Certificates); i++ {
				config.Certificates[i] = certificate{
					CertificateFile: certs[i],
					KeyFile:         keys[i],
				}
			}
		}
	} else {
		configFile, err := os.Open(configPath)
		if err != nil {
			log.Fatalf("fail to open file %s: %v", configPath, err)
		}
		defer func() { _ = configFile.Close() }()
		err = json.NewDecoder(configFile).Decode(&config)
		if err != nil {
			log.Fatalf("fail to parse config: %v", err)
		}
	}

	for _, ma := range config.MethodAddrs {
		ma.MethodBuf = []byte(ma.MethodName)
		if len(ma.MethodBuf) != config.MethodLen {
			log.Fatalf("length of methodName %s not epuals methodLen %d", ma.MethodName, config.MethodLen)
		}
	}

	server()
}

func listenTls() (ln net.Listener, err error) {
	keyPairs := make([]tls.Certificate, len(config.Certificates))
	for i := 0; i < len(config.Certificates); i++ {
		keyPairs[i], err = tls.LoadX509KeyPair(config.Certificates[i].CertificateFile, config.Certificates[i].KeyFile)
		if err != nil {
			return
		}
	}

	tlsConfig := &tls.Config{
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
	tlsConfig.BuildNameToCertificate()

	ln, err = tls.Listen("tcp", config.Listen, tlsConfig)
	return
}

func listenTcp() (ln net.Listener, err error) {
	ln, err = net.Listen("tcp", config.Listen)
	return
}

func server() {
	var ln net.Listener
	var err error

	if len(config.Certificates) != 0 {
		ln, err = listenTls()
	} else {
		ln, err = listenTcp()
	}

	if err != nil {
		log.Fatalf("failed to listen on %s: %v", config.Listen, err)
	}

	defer func() { _ = ln.Close() }()
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
	defer func() { _ = srcConn.Close() }()

	buf := make([]byte, config.MethodLen+1)
	_, err := srcConn.Read(buf)
	if err != nil && err != io.EOF {
		log.Printf("fail to read method:%v\n", err)
		return
	}
	var isSpecifiedMethod bool
	var addr string
	if buf[config.MethodLen] == ' ' {
		for _, ma := range config.MethodAddrs {
			if bytes.Compare(buf[0:config.MethodLen], ma.MethodBuf) == 0 {
				isSpecifiedMethod = true
				addr = ma.Addr
				srcConn = authenticator.Server(srcConn)
				break
			}
		}
	}

	if addr == "" {
		addr = config.BypassAddr
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

	defer func() { _ = dstConn.Close() }()

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
}
