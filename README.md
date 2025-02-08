# Golang Middlewares

[![Release](https://img.shields.io/github/release/thrownew/go-middlewares.svg)](https://github.com/thrownew/go-middlewares/releases/latest)
[![License](https://img.shields.io/github/license/thrownew/go-middlewares.svg)](https://raw.githubusercontent.com/thrownew/go-middlewares/master/LICENSE)
[![Godocs](https://img.shields.io/badge/godoc-reference-blue.svg)](https://godoc.org/github.com/thrownew/go-middlewares)

[![Build Status](https://github.com/thrownew/go-middlewares/workflows/CI/badge.svg)](https://github.com/thrownew/go-middlewares/actions)
[![codecov](https://codecov.io/gh/thrownew/go-middlewares/release/latest/graph/badge.svg)](https://codecov.io/gh/thrownew/go-middlewares)
[![Go Report Card](https://goreportcard.com/badge/github.com/thrownew/go-middlewares)](https://goreportcard.com/report/github.com/thrownew/go-middlewares)

## Client IP Middleware

A secure and flexible middleware for detecting client IP addresses in Go web applications. The middleware handles various scenarios including reverse proxies, CDNs, and load balancers while preventing IP spoofing attacks.

### Features

- Secure IP detection with protection against IP spoofing
- Support for X-Forwarded-For header with trusted proxy validation
- Customizable trusted header detection (e.g., X-Real-IP)
- Flexible detector chain with custom detector support
- Callback function support for custom IP processing
- Configurable rejection handling for undefined IPs

### Usage

```go
func main() {
    r := mux.NewRouter()
    r.Use(
        clientip.NewHandler(
            // Trust X-Forwarded-For only from specific proxy
            clientip.WithXFFDetector(func(ip net.IP) bool {
                return ip.Equal(net.ParseIP("10.0.0.1"))
            }),
            // Add trusted header detector
            clientip.WithTrustedHeaderDetector("X-Real-IP"),
            // Reject response if client ip not detected
            clientip.WithReject(func(w http.ResponseWriter, r *http.Request) {
                w.WriteHeader(http.StatusBadRequest)
                w.Write([]byte("undefined ip"))
            }),
            // Process detected IP
            clientip.WithCallback(func(r *http.Request, ip net.IP) *http.Request {
                return r.WithContext(context.WithValue(r.Context(), "client_ip", ip))
            }),
        ),
    )
}
```

### Security Considerations

The middleware implements several security measures to prevent IP spoofing:

1. **X-Forwarded-For Protection**: Only accepts XFF headers from trusted proxy IPs
2. **Trusted Header Validation**: Allows specifying which headers can be trusted for IP detection
3. **Detector Chain**: Processes multiple IP sources in a specified priority order
4. **Proxy Chain Validation**: Properly handles proxy chains in XFF headers by validating each proxy in the chain

### Configuration Options

- `WithXFFDetector`: Add X-Forwarded-For based detection with trusted proxy validation
- `WithTrustedHeaderDetector`: Add detection from specific trusted headers
- `WithDetector`: Add custom IP detection logic
- `WithCallback`: Process detected IP address
- `WithReject`: Handle cases where IP cannot be determined

### License

This project is licensed under the MIT License - see the LICENSE file for details.

