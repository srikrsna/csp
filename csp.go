package csp

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

const placeholder = "{nonce}"

func init() {
	caddy.RegisterModule(CSP{})
}

var bufferPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

var (
	_ caddy.Provisioner           = (*CSP)(nil)
	_ caddyhttp.MiddlewareHandler = (*CSP)(nil)
	_ caddyfile.Unmarshaler       = (*CSP)(nil)
)

type CSP struct {
	Template   string `json:"template,omitempty"`
	ReportOnly bool   `json:"report_only,omitempty"`

	log    *zap.Logger
	buffer bool
}

func (CSP) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.csp",
		New: func() caddy.Module { return new(CSP) },
	}
}

func (c *CSP) Provision(ctx caddy.Context) error {
	c.log = ctx.Logger(c)

	if strings.Contains(c.Template, placeholder) {
		c.buffer = true
	}

	c.Template = strings.TrimSpace(c.Template)

	return nil
}

func (c *CSP) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if len(c.Template) == 0 {
		return next.ServeHTTP(w, r)
	}

	header := "Content-Security-Policy"
	if c.ReportOnly {
		header = "Content-Security-Policy-Report-Only"
	}

	if !c.buffer {
		return next.ServeHTTP(&cspWriter{ResponseWriterWrapper: &caddyhttp.ResponseWriterWrapper{ResponseWriter: w}, header: header, value: c.Template}, r)
	}

	rec := caddyhttp.NewResponseRecorder(w, nil, func(status int, header http.Header) bool {
		return strings.HasPrefix(header.Get("Content-type"), "text/html")
	})
	if err := next.ServeHTTP(rec, r); err != nil {
		return err
	}

	if !rec.Buffered() {
		return nil
	}

	buf := randPool.Get()
	defer randPool.Put(buf)
	if _, err := rand.Read(buf); err != nil {
		c.log.Error("unable to read from crand", zap.Error(err))
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	nonceBytes := noncePool.Get()
	defer noncePool.Put(nonceBytes)

	base64.RawStdEncoding.Encode(nonceBytes, buf)
	rec.Header().Set(header, strings.ReplaceAll(c.Template, placeholder, "'nonce-"+string(nonceBytes)+"'"))

	res := bytes.ReplaceAll(rec.Buffer().Bytes(), []byte(placeholder), nonceBytes)

	w.WriteHeader(rec.Status())
	if _, err := w.Write(res); err != nil {
		return err
	}

	return nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler. Syntax:
//
//     csp <template> [<report_only>]
//
func (c *CSP) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if !d.Args(&c.Template) {
			return d.ArgErr()
		}

		if d.NextArg() {
			val, err := strconv.ParseBool(d.Val())
			if err != nil {
				return d.SyntaxErr("boolean true or false")
			}

			c.ReportOnly = val
		}

		if d.NextArg() {
			return d.ArgErr()
		}
	}
	return nil
}

type cspWriter struct {
	*caddyhttp.ResponseWriterWrapper

	header, value string
}

var _ caddyhttp.HTTPInterfaces = (*cspWriter)(nil)

func (cw *cspWriter) WriteHeader(status int) {
	if strings.HasPrefix(cw.Header().Get("Content-Type"), "text/html") {
		cw.Header().Set(cw.header, cw.value)
	}

	cw.ResponseWriter.WriteHeader(status)
}

var (
	randPool  = newBytePool(16)
	noncePool = newBytePool(22) // base64.RawStdEncoding.EncodedLen(16)
)

type bytePool struct {
	pool sync.Pool
}

func newBytePool(size int) *bytePool {
	return &bytePool{
		pool: sync.Pool{
			New: func() interface{} {
				b := make([]byte, size)
				return &b
			},
		},
	}
}

func (p *bytePool) Get() []byte {
	return *(p.pool.Get().(*[]byte))
}

func (p *bytePool) Put(b []byte) {
	p.pool.Put(&b)
}
