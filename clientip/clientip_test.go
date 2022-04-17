package clientip

import (
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnitHandlerXFF(t *testing.T) {
	testCases := map[string]struct {
		requestFunc  func() (*http.Request, error)
		reject       bool
		trustedProxy []net.IP
		expected     net.IP
	}{
		"reject": {
			requestFunc: func() (*http.Request, error) {
				return http.NewRequest(http.MethodPost, ``, nil)
			},
			reject: true,
		},
		"remote addr": {
			requestFunc: func() (*http.Request, error) {
				r, err := http.NewRequest(http.MethodPost, ``, nil)
				r.RemoteAddr = "10.137.0.0:13456"
				return r, err
			},
			expected: net.ParseIP("10.137.0.0"),
		},
		"forwarded from trusted proxy many addr": {
			requestFunc: func() (*http.Request, error) {
				r, err := http.NewRequest(http.MethodPost, ``, nil)
				r.RemoteAddr = "10.137.0.0:13456"
				r.Header.Add("X-Forwarded-For", "10.137.0.1, 10.137.0.2, 10.137.0.3")
				r.Header.Add("X-Forwarded-For", "10.137.0.4, 10.137.0.5, 10.137.0.6")
				return r, err
			},
			trustedProxy: []net.IP{net.ParseIP("10.137.0.0")},
			expected:     net.ParseIP("10.137.0.6"),
		},
		"forwarded from trusted proxy one addr": {
			requestFunc: func() (*http.Request, error) {
				r, err := http.NewRequest(http.MethodPost, ``, nil)
				r.RemoteAddr = "10.137.0.0:13456"
				r.Header.Add("X-Forwarded-For", "10.137.0.1")
				return r, err
			},
			trustedProxy: []net.IP{net.ParseIP("10.137.0.0")},
			expected:     net.ParseIP("10.137.0.1"),
		},
		"forwarded from trusted proxy chain: first untrusted is 10.137.0.2": {
			requestFunc: func() (*http.Request, error) {
				r, err := http.NewRequest(http.MethodPost, ``, nil)
				r.RemoteAddr = "10.137.0.0:13456"
				r.Header.Add("X-Forwarded-For", "10.137.0.1, 10.137.0.2, 10.137.0.3")
				r.Header.Add("X-Forwarded-For", "10.137.0.4, 10.137.0.5, 10.137.0.6")
				return r, err
			},
			trustedProxy: []net.IP{
				net.ParseIP("10.137.0.0"),
				net.ParseIP("10.137.0.6"),
				net.ParseIP("10.137.0.5"),
				net.ParseIP("10.137.0.4"),
				net.ParseIP("10.137.0.3"),
			},
			expected: net.ParseIP("10.137.0.2"),
		},
		"forwarded from trusted proxy chain: first untrusted is 10.137.0.6": {
			requestFunc: func() (*http.Request, error) {
				r, err := http.NewRequest(http.MethodPost, ``, nil)
				r.RemoteAddr = "10.137.0.0:13456"
				r.Header.Add("X-Forwarded-For", "10.137.0.1, 10.137.0.2, 10.137.0.3")
				r.Header.Add("X-Forwarded-For", "10.137.0.4, 10.137.0.5, 10.137.0.6")
				return r, err
			},
			trustedProxy: []net.IP{
				net.ParseIP("10.137.0.0"),
			},
			expected: net.ParseIP("10.137.0.6"),
		},
		"forwarded from trusted proxy chain: first untrusted is 10.137.0.5": {
			requestFunc: func() (*http.Request, error) {
				r, err := http.NewRequest(http.MethodPost, ``, nil)
				r.RemoteAddr = "10.137.0.0:13456"
				r.Header.Add("X-Forwarded-For", "10.137.0.1, 10.137.0.2, 10.137.0.3")
				r.Header.Add("X-Forwarded-For", "10.137.0.4, 10.137.0.5, 10.137.0.6")
				return r, err
			},
			trustedProxy: []net.IP{
				net.ParseIP("10.137.0.0"),
				net.ParseIP("10.137.0.6"),
				net.ParseIP("10.137.0.4"),
				net.ParseIP("10.137.0.3"),
				net.ParseIP("10.137.0.2"),
			},
			expected: net.ParseIP("10.137.0.5"),
		},
		"forwarded from trusted proxy chain: first untrusted is 10.137.0.1": {
			requestFunc: func() (*http.Request, error) {
				r, err := http.NewRequest(http.MethodPost, ``, nil)
				r.RemoteAddr = "10.137.0.0:13456"
				r.Header.Add("X-Forwarded-For", "10.137.0.1, 10.137.0.2, 10.137.0.3")
				r.Header.Add("X-Forwarded-For", "10.137.0.4, 10.137.0.5, 10.137.0.6")
				return r, err
			},
			trustedProxy: []net.IP{
				net.ParseIP("10.137.0.0"),
				net.ParseIP("10.137.0.6"),
				net.ParseIP("10.137.0.5"),
				net.ParseIP("10.137.0.4"),
				net.ParseIP("10.137.0.3"),
				net.ParseIP("10.137.0.2"),
			},
			expected: net.ParseIP("10.137.0.1"),
		},
		"forwarded from trusted proxy chain: all trusted": {
			requestFunc: func() (*http.Request, error) {
				r, err := http.NewRequest(http.MethodPost, ``, nil)
				r.RemoteAddr = "10.137.0.0:13456"
				r.Header.Add("X-Forwarded-For", "10.137.0.1, 10.137.0.2, 10.137.0.3")
				r.Header.Add("X-Forwarded-For", "10.137.0.4, 10.137.0.5, 10.137.0.6")
				return r, err
			},
			trustedProxy: []net.IP{
				net.ParseIP("10.137.0.0"),
				net.ParseIP("10.137.0.6"),
				net.ParseIP("10.137.0.5"),
				net.ParseIP("10.137.0.4"),
				net.ParseIP("10.137.0.3"),
				net.ParseIP("10.137.0.2"),
				net.ParseIP("10.137.0.1"),
			},
			expected: net.ParseIP("10.137.0.1"),
		},
		"forwarded from trusted proxy chain: stop on broken": {
			requestFunc: func() (*http.Request, error) {
				r, err := http.NewRequest(http.MethodPost, ``, nil)
				r.RemoteAddr = "10.137.0.0:13456"
				r.Header.Add("X-Forwarded-For", "10.137.0.1, 10.137.0.2, 10.137.0.3")
				r.Header.Add("X-Forwarded-For", "10.137.0.4, 10.137.0.5, -, 10.137.0.6")
				return r, err
			},
			trustedProxy: []net.IP{
				net.ParseIP("10.137.0.0"),
				net.ParseIP("10.137.0.6"),
				net.ParseIP("10.137.0.5"),
				net.ParseIP("10.137.0.4"),
				net.ParseIP("10.137.0.3"),
			},
			expected: net.ParseIP("10.137.0.0"),
		},
		"forwarded from trusted proxy with wrong addr": {
			requestFunc: func() (*http.Request, error) {
				r, err := http.NewRequest(http.MethodPost, ``, nil)
				r.RemoteAddr = "10.137.0.0:13456"
				r.Header.Add("X-Forwarded-For", "10.137.0.1,")
				return r, err
			},
			trustedProxy: []net.IP{net.ParseIP("10.137.0.0")},
			expected:     net.ParseIP("10.137.0.0"),
		},
		"forwarded from untrusted proxy": {
			requestFunc: func() (*http.Request, error) {
				r, err := http.NewRequest(http.MethodPost, ``, nil)
				r.RemoteAddr = "10.137.0.0:13456"
				r.Header.Add("X-Forwarded-For", "10.137.0.1, 10.137.0.2, 10.137.0.3")
				r.Header.Add("X-Forwarded-For", "10.137.0.4, 10.137.0.5, 10.137.0.6")
				return r, err
			},
			trustedProxy: []net.IP{
				net.ParseIP("10.137.0.6"),
				net.ParseIP("10.137.0.5"),
				net.ParseIP("10.137.0.4"),
				net.ParseIP("10.137.0.3"),
			},
			expected: net.ParseIP("10.137.0.0"),
		},
	}

	for name := range testCases {
		c := testCases[name]
		t.Run(name, func(t *testing.T) {
			opts := []Option{
				WithXFFDetector(func(ip net.IP) bool {
					for _, tip := range c.trustedProxy {
						if ip.Equal(tip) {
							return true
						}
					}
					return false
				}),
				WithCallback(func(r *http.Request, ip net.IP) *http.Request {
					assert.Equal(t, c.expected.String(), ip.String())
					return r
				}),
			}
			if c.reject {
				opts = append(opts, WithReject(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte("rejected")) // nolint: errcheck
				}))
			}

			h := NewHandler(opts...)

			req, err := c.requestFunc()
			require.NoError(t, err)

			w := httptest.NewRecorder()

			h(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("executed")) // nolint: errcheck
			})).ServeHTTP(w, req)

			resp := w.Result()
			body, err := ioutil.ReadAll(resp.Body)
			require.NoError(t, err)

			if c.reject {
				assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
				assert.Equal(t, "rejected", string(body))
			} else {
				assert.Equal(t, http.StatusOK, resp.StatusCode)
				assert.Equal(t, "executed", string(body))
			}
		})
	}
}
