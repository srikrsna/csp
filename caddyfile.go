package csp

import (
	"strconv"

	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("csp", parseCaddyfile)
}

// parseCaddyfile sets up the handler from Caddyfile tokens. Syntax:
//
//     csp [<matcher>] {
//         template <types...>
//         report_only <path>
//     }
//
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	t := new(CSP)
	for h.Next() {
		for h.NextBlock(0) {
			switch h.Val() {
			case "template":
				if !h.Args(&t.Template) {
					return nil, h.ArgErr()
				}
			case "report_only":
				var val string
				if !h.Args(&val) {
					return nil, h.ArgErr()
				}

				v, err := strconv.ParseBool(val)
				if err != nil {
					return nil, err
				}

				t.ReportOnly = v
			}
		}
	}
	return t, nil
}
