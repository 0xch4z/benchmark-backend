package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"unsafe"

	"github.com/valyala/fasthttp"
	"golang.org/x/sys/unix"
)

var (
	addr        string
	serviceName string
	compress    bool
	debug       bool
	concurrency int
)

func init() {
	flag.StringVar(&addr, "addr", ":8080", "Address to listen on")
	flag.StringVar(&serviceName, "service-name", "backend0", "Name of the service to be displayed in response")
	flag.BoolVar(&compress, "compress", false, "Compress the response payload")
	flag.BoolVar(&debug, "debug", false, "Debug request host and remote IP")
	flag.IntVar(&concurrency, "concurrency", 1, "Number of listening sockets (>=2 uses SO_REUSEPORT)")
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
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	errCh := make(chan error, concurrency)

	if concurrency > 1 {
		for i := 0; i < concurrency; i++ {
			ln, err := listenWithReusePort("tcp", addr)
			if err != nil {
				log.Fatalf("failed to create listener %d on %s: %v", i, addr, err)
			}
			log.Printf("listening (socket %d) on %s with SO_REUSEPORT", i, addr)
			go func(idx int, l net.Listener) {
				if err := srv.Serve(l); err != nil {
					errCh <- err
				}
			}(i, ln)
		}
	} else {
		go func() {
			errCh <- srv.ListenAndServe(addr)
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
