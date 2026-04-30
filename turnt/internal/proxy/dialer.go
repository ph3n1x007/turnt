package proxy

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/praetorian-inc/turnt/internal/logger"
)

type HTTPConnectDialer struct {
	proxyAddr string
	proxyUser string
	proxyPass string
}

func NewHTTPConnectDialer(proxyURL string) (*HTTPConnectDialer, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}

	host := u.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "8080")
	}

	d := &HTTPConnectDialer{proxyAddr: host}

	if u.User != nil {
		d.proxyUser = u.User.Username()
		d.proxyPass, _ = u.User.Password()
	}

	return d, nil
}

func (d *HTTPConnectDialer) Dial(network, addr string) (net.Conn, error) {
	logger.Debug("Proxy dialing %s via %s", addr, d.proxyAddr)

	conn, err := net.DialTimeout("tcp", d.proxyAddr, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to proxy %s: %w", d.proxyAddr, err)
	}

	br := bufio.NewReader(conn)

	if err := writeConnectRequest(conn, addr, ""); err != nil {
		conn.Close()
		return nil, err
	}

	resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read proxy response: %w", err)
	}

	if resp.StatusCode == http.StatusOK {
		logger.Debug("Proxy tunnel established (no auth required)")
		return conn, nil
	}

	if resp.StatusCode != http.StatusProxyAuthRequired {
		conn.Close()
		return nil, fmt.Errorf("proxy returned unexpected status: %s", resp.Status)
	}

	authHeaders := resp.Header.Values("Proxy-Authenticate")
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	negotiateSupported := false
	basicSupported := false
	for _, h := range authHeaders {
		lower := strings.ToLower(h)
		if strings.HasPrefix(lower, "negotiate") {
			negotiateSupported = true
		}
		if strings.HasPrefix(lower, "basic") {
			basicSupported = true
		}
	}

	if negotiateSupported {
		logger.Info("Proxy requires Negotiate auth, attempting Kerberos/SSPI")

		if shouldCloseConn(resp) {
			conn.Close()
			conn, err = net.DialTimeout("tcp", d.proxyAddr, 30*time.Second)
			if err != nil {
				return nil, fmt.Errorf("failed to reconnect to proxy: %w", err)
			}
			br = bufio.NewReader(conn)
		}

		return negotiateWithProxy(conn, br, addr, d.proxyAddr)
	}

	if basicSupported && d.proxyUser != "" {
		logger.Info("Proxy requires Basic auth")

		if shouldCloseConn(resp) {
			conn.Close()
			conn, err = net.DialTimeout("tcp", d.proxyAddr, 30*time.Second)
			if err != nil {
				return nil, fmt.Errorf("failed to reconnect to proxy: %w", err)
			}
			br = bufio.NewReader(conn)
		}

		creds := base64.StdEncoding.EncodeToString([]byte(d.proxyUser + ":" + d.proxyPass))
		if err := writeConnectRequest(conn, addr, "Basic "+creds); err != nil {
			conn.Close()
			return nil, err
		}

		resp, err = http.ReadResponse(br, &http.Request{Method: "CONNECT"})
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to read proxy response: %w", err)
		}

		if resp.StatusCode == http.StatusOK {
			logger.Debug("Proxy tunnel established with Basic auth")
			return conn, nil
		}

		conn.Close()
		return nil, fmt.Errorf("proxy Basic auth failed: %s", resp.Status)
	}

	conn.Close()
	return nil, fmt.Errorf("no suitable proxy auth method (proxy offered: %s)", strings.Join(authHeaders, ", "))
}

func writeConnectRequest(conn net.Conn, addr, authHeader string) error {
	var sb strings.Builder
	fmt.Fprintf(&sb, "CONNECT %s HTTP/1.1\r\n", addr)
	fmt.Fprintf(&sb, "Host: %s\r\n", addr)
	if authHeader != "" {
		fmt.Fprintf(&sb, "Proxy-Authorization: %s\r\n", authHeader)
	}
	sb.WriteString("\r\n")

	_, err := io.WriteString(conn, sb.String())
	return err
}

func shouldCloseConn(resp *http.Response) bool {
	if resp.Close {
		return true
	}
	if resp.ProtoMajor == 1 && resp.ProtoMinor == 0 {
		return resp.Header.Get("Connection") != "keep-alive"
	}
	return false
}
