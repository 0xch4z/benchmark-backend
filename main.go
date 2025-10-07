package main

import (
	"flag"
	"log"
	"unsafe"

	"github.com/valyala/fasthttp"
)

var (
	addr        string
	serviceName string
	compress    bool
	debug       bool
)

func init() {
	flag.StringVar(&addr, "addr", ":8080", "Address to listen on")
	flag.StringVar(&serviceName, "service-name", "backend0", "Name of the service to be displayed in response")
	flag.BoolVar(&compress, "compress", false, "Compress the response payload")
	flag.BoolVar(&debug, "debug", false, "Debug request host and remote IP")
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

	if err := srv.ListenAndServe(addr); err != nil {
		log.Fatalf("failed to listen at %s: %v", addr, err)
	}
}

func newRequestHandler() fasthttp.RequestHandler {
	contentType := []byte("text/plan; charset=utf8")
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
