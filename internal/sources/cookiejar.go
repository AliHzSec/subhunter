package sources

import (
	"net/http"
	"net/url"
	"sync"
)

// simpleCookieJar is a thread-safe cookie jar that also exposes Set for programmatic use.
type simpleCookieJar struct {
	mu      sync.Mutex
	cookies map[string]map[string]string // domain -> name -> value
}

func newSimpleCookieJar() *simpleCookieJar {
	return &simpleCookieJar{cookies: map[string]map[string]string{}}
}

func (j *simpleCookieJar) Set(domain, name, value string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.cookies[domain] == nil {
		j.cookies[domain] = map[string]string{}
	}
	j.cookies[domain][name] = value
}

func (j *simpleCookieJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	j.mu.Lock()
	defer j.mu.Unlock()
	host := u.Hostname()
	if j.cookies[host] == nil {
		j.cookies[host] = map[string]string{}
	}
	for _, c := range cookies {
		j.cookies[host][c.Name] = c.Value
	}
}

func (j *simpleCookieJar) Cookies(u *url.URL) []*http.Cookie {
	j.mu.Lock()
	defer j.mu.Unlock()
	host := u.Hostname()
	var out []*http.Cookie
	for name, value := range j.cookies[host] {
		out = append(out, &http.Cookie{Name: name, Value: value})
	}
	return out
}

func buildHTTPClientWithJar(proxy string, timeoutSecs int, jar http.CookieJar) *http.Client {
	c := buildHTTPClient(proxy, timeoutSecs)
	c.Jar = jar
	return c
}
