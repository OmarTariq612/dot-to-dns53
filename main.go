package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

const (
	timeoutDuration     = 5 * time.Second
	maxDNSMessageLength = 512
	dnsServerAddr       = "8.8.8.8:53"
	certificate         = "site.crt"
	key                 = "site.key"
)

type Server struct {
	ctx       context.Context
	addr      string
	maxIdle   time.Duration
	tlsConfig *tls.Config
}

func NewServer(ctx context.Context, addr string, maxIdle time.Duration, tlsConfig *tls.Config) *Server {
	return &Server{
		ctx:       ctx,
		addr:      addr,
		maxIdle:   maxIdle,
		tlsConfig: tlsConfig,
	}
}

func (s *Server) ListenAndServeTLS(certFile, keyFile string) error {
	if s.addr == "" {
		s.addr = "localhost:853"
	}

	l, err := net.Listen("tcp", s.addr)
	if err != nil {
		panic(err)
	}

	if s.ctx != nil {
		go func() {
			<-s.ctx.Done()
			l.Close()
		}()
	}

	return s.ServeTLS(l, certFile, keyFile)
}

func (s *Server) ServeTLS(l net.Listener, certFile, keyFile string) error {
	if s.tlsConfig == nil {
		s.tlsConfig = &tls.Config{
			CurvePreferences:         []tls.CurveID{tls.CurveP256},
			MinVersion:               tls.VersionTLS13,
			PreferServerCipherSuites: true,
		}
	}

	if len(s.tlsConfig.Certificates) == 0 && s.tlsConfig.GetCertificate == nil {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			panic(err)
		}
		s.tlsConfig.Certificates = []tls.Certificate{cert}
	}

	tlsListener := tls.NewListener(l, s.tlsConfig)

	for {
		conn, err := tlsListener.Accept()
		if err != nil {
			panic(err)
		}

		go func() {
			defer conn.Close()
			for {
				if s.maxIdle > 0 {
					err := conn.SetDeadline(time.Now().Add(s.maxIdle))
					if err != nil {
						panic(err)
					}
				}

				var lengthRaw [2]byte
				var buf [maxDNSMessageLength]byte

				// read length
				_, err = io.ReadFull(conn, lengthRaw[:])
				if err != nil {
					log.Println("error reading the length:", err)
					return
				}

				length := binary.BigEndian.Uint16(lengthRaw[:])

				// read query
				_, err = io.ReadFull(conn, buf[:length])
				if err != nil {
					fmt.Println("error reading the buf:", err)
					return
				}

				go func() {
					dnsConn, err := net.Dial("udp", dnsServerAddr)
					if err != nil {
						panic(err)
					}
					defer dnsConn.Close()

					_, err = dnsConn.Write(buf[:length])
					if err != nil {
						fmt.Println("error writing the buf to DNS:", err)
						return
					}

					dnsConn.SetReadDeadline(time.Now().Add(timeoutDuration))
					n, err := dnsConn.Read(buf[:])
					if err != nil {
						fmt.Println("error reading the buf from the DNS:", err)
						return
					}

					binary.BigEndian.PutUint16(lengthRaw[:], uint16(n))

					_, err = conn.Write(append(lengthRaw[:], buf[:n]...))
					if err != nil {
						fmt.Println("error writing the buf:", err)
						return
					}
				}()
			}
		}()
	}
}

func main() {
	s := NewServer(context.Background(), ":853", 2*time.Minute, nil)
	log.Println(s.ListenAndServeTLS(certificate, key))
}
