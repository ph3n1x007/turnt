//go:build !windows

package proxy

func detectSystemProxy() string {
	return ""
}
