package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unsafe"

	"github.com/dgrr/http2"
	"github.com/valyala/fasthttp"
	"golang.org/x/sys/unix"
)

var (
	addr        string
	serviceName string
	compress    bool
	debug       bool
	concurrency int
	tlsCert     string
	tlsKey      string
	enableH2    bool
)

func init() {
	flag.StringVar(&addr, "addr", ":9090", "Address to listen on")
	flag.StringVar(&serviceName, "service-name", "backend0", "Name of the service to be displayed in response")
	flag.BoolVar(&compress, "compress", false, "Compress the response payload")
	flag.BoolVar(&debug, "debug", false, "Debug request host and remote IP")
	flag.IntVar(&concurrency, "concurrency", 1, "Number of listening sockets (>=2 uses SO_REUSEPORT)")
	flag.StringVar(&tlsCert, "tls-cert", "", "Path to TLS certificate (PEM)")
	flag.StringVar(&tlsKey, "tls-key", "", "Path to TLS private key (PEM)")
	flag.BoolVar(&enableH2, "http2", false, "Enable HTTP/2 (requires TLS)")
}

func main() {
	flag.Parse()

	requestHandler := newRequestHandler()
	var handler fasthttp.RequestHandler

	if compress {
		handler = fasthttp.CompressHandlerLevel(requestHandler, fasthttp.CompressBestSpeed)
	} else {
		handler = fasthttp.CompressHandlerLevel(requestHandler, fasthttp.CompressNoCompression)
	}

	srv := &fasthttp.Server{
		Handler:                       handler,
		NoDefaultDate:                 true,
		NoDefaultServerHeader:         true,
		NoDefaultContentType:          true,
		DisableHeaderNamesNormalizing: true,
		ReduceMemoryUsage:             false,
		LogAllErrors:                  false,
		IdleTimeout:                   1 * time.Second, // crazy (:
	}

	var tlsCfg *tls.Config
	tlsEnabled := tlsCert != "" && tlsKey != ""

	if tlsEnabled {
		cert, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
		if err != nil {
			log.Fatalf("failed to load TLS cert/key: %v", err)
		}

		alpn := []string{"http/1.1"}
		if enableH2 {
			alpn = []string{"h2", "http/1.1"}
		}

		tlsCfg = &tls.Config{
			Certificates:     []tls.Certificate{cert},
			MinVersion:       tls.VersionTLS13,
			MaxVersion:       tls.VersionTLS13,
			NextProtos:       alpn,
			CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
		}
	}

	if enableH2 {
		if !tlsEnabled {
			log.Fatalf("-http2 requires TLS; provide -tls-cert and -tls-key")
		}

		http2.ConfigureServer(srv, http2.ServerConfig{
			Debug: debug,
		})
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	errCh := make(chan error, concurrency)

	serve := func(ln net.Listener) {
		if tlsEnabled {
			ln = tls.NewListener(ln, tlsCfg)
		}
		if err := srv.Serve(ln); err != nil {
			errCh <- err
		}
	}

	if concurrency > 1 {
		for i := 0; i < concurrency; i++ {
			ln, err := listenWithReusePort("tcp", addr)
			if err != nil {
				log.Fatalf("failed to create listener %d on %s: %v", i, addr, err)
			}

			log.Printf("listening (socket %d) on %s %s", i, addr, ternary(tlsEnabled, "(TLS)", "(plaintext)"))
			go serve(ln)
		}
	} else {
		go func() {
			lc := net.ListenConfig{}
			ln, err := lc.Listen(context.Background(), "tcp", addr)
			if err != nil {
				errCh <- err
				return
			}

			log.Printf("listening on %s %s", addr, ternary(tlsEnabled, "(TLS)", "(plaintext)"))
			serve(ln)
		}()
	}

	select {
	case sig := <-stop:
		log.Printf("received signal %s, shutting down...", sig)
		if err := srv.Shutdown(); err != nil {
			log.Printf("shutdown error: %v", err)
		}
	case err := <-errCh:
		log.Fatalf("server error: %v", err)
	}
}

func listenWithReusePort(network, address string) (net.Listener, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var ctrlErr error
			if err := c.Control(func(fd uintptr) {
				// SO_REUSEPORT and SO_REUSEADDR
				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
					ctrlErr = err
					return
				}
				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
					ctrlErr = err
					return
				}
			}); err != nil {
				return err
			}
			return ctrlErr
		},
	}
	return lc.Listen(context.Background(), network, address)
}

func newRequestHandler() fasthttp.RequestHandler {
	contentType := []byte("text/plain; charset=utf-8")
	payload := []byte("Ok: " + serviceName + "\n")

	if debug {
		return func(ctx *fasthttp.RequestCtx) {
			hostBytes := ctx.Host()
			host := *(*string)(unsafe.Pointer(&hostBytes))
			ctx.SetContentTypeBytes(contentType)
			ctx.Response.SetBodyRaw(append(payload, []byte("("+host+"); IP:"+ctx.RemoteIP().String())...))
		}
	}

	return func(ctx *fasthttp.RequestCtx) {
		ctx.SetContentTypeBytes(contentType)
		ctx.Response.SetBodyRaw(payload)
	}
}

func ternary[T any](b bool, t, f T) T {
	if b {
		return t
	}
	return f
}
