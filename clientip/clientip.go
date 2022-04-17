package clientip

import (
	"net"
	"net/http"
	"strings"
)

const (
	headerForwardedFor = `X-Forwarded-For`
)

type (
	// Option for customize handler
	Option func(*handler)

	// Callback function will be called after ip detection
	Callback func(r *http.Request, ip net.IP) *http.Request

	handler struct {
		next      http.Handler
		callback  Callback
		detectors []func(r *http.Request) net.IP
		reject    http.HandlerFunc
	}
)

// NewHandler constructor
// Example:
//  func main() {
//      r := mux.NewRouter()
//      r.Use(
//          clientip.NewHandler(
//              clientip.WithXFFDetector(func(ip net.IP) bool {
//              return ip.Equal(net.ParseIP(`10.0.0.1`))
//          }),
//          clientip.WithTrustedHeaderDetector(`X-Test-Ip`),
//          clientip.WithReject(func(w http.ResponseWriter, r *http.Request) {
//              w.WriteHeader(http.StatusBadRequest)
//              _, _ = w.Write([]byte("undefined ip"))
//         }),
//         clientip.WithCallback(func(r *http.Request, ip net.IP) *http.Request {
//             return r.WithContext(context.WithValue(r.Context(), `client_ip`, ip))
//         }),
//     ))
//  }
//
func NewHandler(opts ...Option) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return buildHandler(h, opts...)
	}
}

func buildHandler(next http.Handler, opts ...Option) *handler {
	h := &handler{
		next: next,
		// Default detector list
		detectors: []func(r *http.Request) net.IP{
			func(r *http.Request) net.IP {
				if addr, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr)); err == nil {
					return net.ParseIP(addr)
				}
				return nil
			},
		},
	}
	for _, optionF := range opts {
		optionF(h)
	}
	return h
}

// WithCallback call on ip detection
func WithCallback(c Callback) Option {
	return func(h *handler) {
		h.callback = c
	}
}

// WithDetector add custom ip detector into detectors chain
// Last detector will be called first
func WithDetector(detector func(r *http.Request) net.IP) Option {
	return func(h *handler) {
		h.detectors = append(h.detectors, detector)
	}
}

// WithXFFDetector add detector based on X-Forwarded-For headers.
// The client can set the X-Forwarded-For header to any arbitrary value it wants.
// Usage X-Forwarded-For without check trusted proxies may lead to ip spoofing.
// Header example: `X-Forwarded-For: <client>, <proxy1>, <proxy2>`
func WithXFFDetector(trustedProxy func(ip net.IP) bool) Option {
	return WithDetector(func(r *http.Request) net.IP {
		// Allow X-Forwarded-For usage only from trusted proxies
		if addr, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr)); err == nil {
			if !trustedProxy(net.ParseIP(addr)) {
				return nil
			}
		}
		var chain []net.IP
		// Fill full chain of ip addresses from all headers
		for _, forwarded := range r.Header.Values(headerForwardedFor) {
			if strings.Contains(forwarded, `,`) {
				for _, addr := range strings.Split(forwarded, `,`) {
					chain = append(chain, net.ParseIP(strings.TrimSpace(addr)))
				}
			} else {
				chain = append(chain, net.ParseIP(strings.TrimSpace(forwarded)))
			}
		}
		// Walk back chain and find first untrusted proxy addr
		for i := len(chain) - 1; i >= 0; i-- {
			if !trustedProxy(chain[i]) {
				return chain[i]
			}
		}
		// If all chain trusted just return last trusted ip
		if len(chain) > 0 {
			return chain[0]
		}
		return nil
	})
}

// WithTrustedHeaderDetector detect ip from trusted header
// For example you may use X-Real-Ip header.
// The client can set any header's to any arbitrary value it wants.
// Untrusted header usage may lead to ip spoofing.
func WithTrustedHeaderDetector(name string) Option {
	return WithDetector(func(r *http.Request) net.IP {
		if addr := strings.TrimSpace(r.Header.Get(name)); addr != "" {
			return net.ParseIP(addr)
		}
		return nil
	})
}

// WithReject request handler
func WithReject(reject http.HandlerFunc) Option {
	return func(h *handler) {
		h.reject = reject
	}
}

// ServeHTTP implementation
func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var ip net.IP
	for i := len(h.detectors) - 1; i >= 0; i-- {
		if detected := h.detectors[i](r); detected != nil && !detected.IsUnspecified() {
			ip = detected
			break
		}
	}
	// Reject request and stop chain
	if h.reject != nil && ip == nil {
		h.reject(w, r)
		return
	}
	if h.callback != nil {
		r = h.callback(r, ip)
	}
	h.next.ServeHTTP(w, r)
}
