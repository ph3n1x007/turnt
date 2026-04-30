//go:build windows

package proxy

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/praetorian-inc/turnt/internal/logger"
)

var (
	secur32 = syscall.NewLazyDLL("secur32.dll")

	procAcquireCredentialsHandle  = secur32.NewProc("AcquireCredentialsHandleW")
	procInitializeSecurityContext = secur32.NewProc("InitializeSecurityContextW")
	procFreeCredentialsHandle     = secur32.NewProc("FreeCredentialsHandle")
	procDeleteSecurityContext     = secur32.NewProc("DeleteSecurityContext")
)

const (
	secpkgCredOutbound = 2

	iscReqMutualAuth     = 0x00000002
	iscReqReplayDetect   = 0x00000004
	iscReqSequenceDetect = 0x00000008
	iscReqConfidentiality = 0x00000010
	iscReqConnection     = 0x00000800

	secBufferToken   = 2
	secBufferVersion = 0

	secEOK              = 0
	secIContinueNeeded  = 0x00090312

	securityNativeDrep = 0x00000010
)

type secHandle struct {
	Lower uintptr
	Upper uintptr
}

type secBuffer struct {
	Size   uint32
	Type   uint32
	Buffer uintptr
}

type secBufferDesc struct {
	Version uint32
	Count   uint32
	Buffers *secBuffer
}

type sspiContext struct {
	credHandle secHandle
	ctxHandle  secHandle
	spn        *uint16
	hasContext  bool
}

func newSSPIContext(spn string) (*sspiContext, error) {
	ctx := &sspiContext{}

	spnUTF16, err := syscall.UTF16PtrFromString(spn)
	if err != nil {
		return nil, fmt.Errorf("failed to encode SPN: %w", err)
	}
	ctx.spn = spnUTF16

	packageName, _ := syscall.UTF16PtrFromString("Negotiate")
	var expiry int64

	ret, _, _ := procAcquireCredentialsHandle.Call(
		0,
		uintptr(unsafe.Pointer(packageName)),
		secpkgCredOutbound,
		0, 0, 0, 0,
		uintptr(unsafe.Pointer(&ctx.credHandle)),
		uintptr(unsafe.Pointer(&expiry)),
	)

	runtime.KeepAlive(packageName)

	if ret != secEOK {
		return nil, fmt.Errorf("SSPI AcquireCredentialsHandle failed: %s", sspiErrorMessage(ret))
	}

	return ctx, nil
}

func (c *sspiContext) step(serverToken []byte) ([]byte, bool, error) {
	outputBuf := make([]byte, 12288)

	outSecBuf := secBuffer{
		Size:   uint32(len(outputBuf)),
		Type:   secBufferToken,
		Buffer: uintptr(unsafe.Pointer(&outputBuf[0])),
	}
	outDesc := secBufferDesc{
		Version: secBufferVersion,
		Count:   1,
		Buffers: &outSecBuf,
	}

	var inputDescPtr uintptr
	var inSecBuf secBuffer
	var inDesc secBufferDesc

	if serverToken != nil && len(serverToken) > 0 {
		inSecBuf = secBuffer{
			Size:   uint32(len(serverToken)),
			Type:   secBufferToken,
			Buffer: uintptr(unsafe.Pointer(&serverToken[0])),
		}
		inDesc = secBufferDesc{
			Version: secBufferVersion,
			Count:   1,
			Buffers: &inSecBuf,
		}
		inputDescPtr = uintptr(unsafe.Pointer(&inDesc))
	}

	var ctxIn uintptr
	if c.hasContext {
		ctxIn = uintptr(unsafe.Pointer(&c.ctxHandle))
	}

	var contextAttr uint32
	var contextExpiry int64

	contextReq := uintptr(iscReqMutualAuth | iscReqReplayDetect | iscReqSequenceDetect | iscReqConfidentiality | iscReqConnection)

	ret, _, _ := procInitializeSecurityContext.Call(
		uintptr(unsafe.Pointer(&c.credHandle)),
		ctxIn,
		uintptr(unsafe.Pointer(c.spn)),
		contextReq,
		0,
		securityNativeDrep,
		inputDescPtr,
		0,
		uintptr(unsafe.Pointer(&c.ctxHandle)),
		uintptr(unsafe.Pointer(&outDesc)),
		uintptr(unsafe.Pointer(&contextAttr)),
		uintptr(unsafe.Pointer(&contextExpiry)),
	)

	runtime.KeepAlive(outputBuf)
	runtime.KeepAlive(outSecBuf)
	runtime.KeepAlive(outDesc)
	runtime.KeepAlive(serverToken)
	runtime.KeepAlive(inSecBuf)
	runtime.KeepAlive(inDesc)

	if ret != secEOK && ret != secIContinueNeeded {
		return nil, false, fmt.Errorf("SSPI InitializeSecurityContext failed: %s", sspiErrorMessage(ret))
	}

	c.hasContext = true

	token := make([]byte, outSecBuf.Size)
	copy(token, outputBuf[:outSecBuf.Size])

	return token, ret == secIContinueNeeded, nil
}

func (c *sspiContext) close() {
	if c.hasContext {
		procDeleteSecurityContext.Call(uintptr(unsafe.Pointer(&c.ctxHandle)))
	}
	procFreeCredentialsHandle.Call(uintptr(unsafe.Pointer(&c.credHandle)))
}

func sspiErrorMessage(code uintptr) string {
	switch code {
	case 0x80090311:
		return "no credentials available (not logged in with a domain account?)"
	case 0x80090303:
		return "target unknown (proxy hostname not resolvable via Kerberos?)"
	case 0x80090302:
		return "Negotiate provider not available"
	case 0x80090308:
		return "token invalid or expired"
	case 0x80090322:
		return "SPN mismatch"
	case 0x80090006:
		return "insufficient memory for security operation"
	default:
		return fmt.Sprintf("SSPI error 0x%x", code)
	}
}

func negotiateWithProxy(conn net.Conn, br *bufio.Reader, targetAddr, proxyAddr string) (net.Conn, error) {
	proxyHost, _, err := net.SplitHostPort(proxyAddr)
	if err != nil {
		proxyHost = proxyAddr
	}

	spn := "HTTP/" + proxyHost
	logger.Debug("Using SPN: %s", spn)

	ctx, err := newSSPIContext(spn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to initialize SSPI: %w", err)
	}
	defer ctx.close()

	var serverToken []byte

	for round := 0; round < 5; round++ {
		outToken, continueNeeded, err := ctx.step(serverToken)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("Kerberos authentication failed: %w", err)
		}

		authValue := "Negotiate " + base64.StdEncoding.EncodeToString(outToken)

		if err := writeConnectRequest(conn, targetAddr, authValue); err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to send auth request: %w", err)
		}

		resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to read auth response: %w", err)
		}

		if resp.StatusCode == http.StatusOK {
			logger.Info("Proxy tunnel established with Kerberos/Negotiate auth")
			return conn, nil
		}

		if resp.StatusCode != http.StatusProxyAuthRequired || !continueNeeded {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			conn.Close()
			return nil, fmt.Errorf("proxy Negotiate auth failed: %s", resp.Status)
		}

		authHeader := ""
		for _, v := range resp.Header.Values("Proxy-Authenticate") {
			if strings.HasPrefix(strings.ToLower(v), "negotiate") {
				authHeader = v
				break
			}
		}

		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[1] == "" {
			conn.Close()
			return nil, fmt.Errorf("proxy returned Negotiate challenge without token")
		}

		serverToken, err = base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to decode server challenge: %w", err)
		}

		if shouldCloseConn(resp) {
			conn.Close()
			conn, err = net.DialTimeout("tcp", proxyAddr, 30*time.Second)
			if err != nil {
				return nil, fmt.Errorf("failed to reconnect to proxy for auth continuation: %w", err)
			}
			br = bufio.NewReader(conn)
		}
	}

	conn.Close()
	return nil, fmt.Errorf("Negotiate auth exceeded maximum rounds")
}
