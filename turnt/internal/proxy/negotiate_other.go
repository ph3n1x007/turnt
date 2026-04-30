//go:build !windows

package proxy

import (
	"bufio"
	"fmt"
	"net"
)

func negotiateWithProxy(conn net.Conn, br *bufio.Reader, targetAddr, proxyAddr string) (net.Conn, error) {
	conn.Close()
	return nil, fmt.Errorf("Negotiate/Kerberos proxy authentication requires Windows (SSPI)")
}
