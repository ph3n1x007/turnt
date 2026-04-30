package proxy

import "os"

func DetectProxy() string {
	for _, env := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		if v := os.Getenv(env); v != "" {
			return v
		}
	}
	return detectSystemProxy()
}
