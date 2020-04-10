package navigator

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/valyala/fasthttp"
	"golang.org/x/net/proxy"
)

//Navigator @ navigator structure.
type Navigator struct {
	client          fasthttp.Client
	cookies         []*fasthttp.Cookie
	useCookies      bool
	followRedirects bool
	Timeout         time.Duration
	userAgent       string
	// Logger          log.Logger
}

//Response @
type Response struct {
	StatusCode   int
	ResponseBody string
	Header       map[string]string
}

const (
	//DefaultPostFormType is default post type
	// is `application/x-www-form-urlencoded`
	DefaultPostFormType = "application/x-www-form-urlencoded"
)

//Create @ returns an Navigator instance
func Create(useCookie bool, followRedirects bool) *Navigator {
	nav := Navigator{
		client: fasthttp.Client{
			ReadTimeout:         time.Minute,
			WriteTimeout:        time.Minute,
			MaxIdleConnDuration: time.Second * 5,
		},
	}
	nav.Timeout = time.Minute
	nav.useCookies = useCookie
	nav.followRedirects = followRedirects
	nav.client.Dial = func(addr string) (conn net.Conn, err error) {
		return fasthttp.DialTimeout(addr, nav.Timeout)
	}

	return &nav
}

//SetSOCKS5 @ set SOCKS5 proxy
func (n *Navigator) SetSOCKS5(address string, proxyAuth proxy.Auth) error {
	if address == "" {
		n.client.Dial = fasthttp.Dial
	}

	dialer, err := proxy.SOCKS5("tcp", address, &proxyAuth, &net.Dialer{Timeout: n.Timeout})
	if err != nil {
		// n.Logger.Printf("Dialer: %#+v\n", dialer)
		// n.Logger.Println(err.Error())
		return err
	}

	n.client.Dial = func(addr string) (net.Conn, error) {
		if err != nil {
			return nil, err
		}
		return dialer.Dial("tcp", addr)
	}

	return nil
}

//SetUserAgent @ set User-Agent
func (n *Navigator) SetUserAgent(userAgent string) {
	n.userAgent = userAgent
}

//GetUserAgent @ returns User-Agent
func (n *Navigator) GetUserAgent() string {
	return n.userAgent
}

func (n *Navigator) setUpTemporary(request *fasthttp.Request) {
	request.Header.Set("Accept", "*")
	request.Header.SetConnectionClose()

	if n.userAgent != "" {
		request.Header.Set("User-Agent", n.userAgent)
	}
}

func parseHeaders(header string) map[string]string {
	headers := make(map[string]string)
	re := regexp.MustCompile(`(?m)^(.+?):\s(.+?)\r$`)
	matches := re.FindAllStringSubmatch(header, -1)

	for _, match := range matches {
		headers[match[1]] = match[2]
	}

	return headers
}

//Head @
func (n *Navigator) Head(url string) (response Response, err error) {
	resp, req := fasthttp.AcquireResponse(), fasthttp.AcquireRequest()
	defer func() {
		fasthttp.ReleaseResponse(resp)
		fasthttp.ReleaseRequest(req)
	}()

	req.Header.SetMethod("HEAD")
	req.Header.SetRequestURI(url)
	n.setUpTemporary(req)

	for _, c := range n.cookies {
		req.Header.SetCookieBytesKV(c.Key(), c.Value())
	}

	err = nil

	if n.followRedirects && n.useCookies {
		err = n.doCookieWithRedirects(req, resp)
	} else if n.followRedirects && !n.useCookies {
		err = n.client.DoRedirects(req, resp, 10)
	} else {
		err = n.client.Do(req, resp)
	}

	if err != nil {
		if strings.Contains(err.Error(), "EOF") {
			// n.Logger.Printf("eof err: %v\n", err)
			// n.Logger.Println("EOF err.")
			return n.Head(url)
		}
		if strings.Contains(err.Error(), "unexpected protocol") {
			// n.Logger.Printf("unprotocol err: %v\n", err)
			// n.Logger.Println("Protocol err.")
			return n.Head(url)
		}
		return response, err
	}

	response.StatusCode = resp.StatusCode()
	response.ResponseBody = string(resp.Body())
	response.Header = parseHeaders(resp.Header.String())

	// n.Logger.Println(resp.Header.String())

	resp.Header.VisitAllCookie(func(key, value []byte) {
		c := fasthttp.AcquireCookie()
		if n.useCookies == false {
			defer fasthttp.ReleaseCookie(c)
		}
		c.ParseBytes(value)

		n.cookies = append(n.cookies, c)
	})

	return response, err
}

//Get @
func (n *Navigator) Get(url string) (response Response, err error) {
	resp, req := fasthttp.AcquireResponse(), fasthttp.AcquireRequest()
	defer func() {
		fasthttp.ReleaseResponse(resp)
		fasthttp.ReleaseRequest(req)
	}()

	req.Header.SetMethod("GET")
	req.Header.SetRequestURI(url)
	n.setUpTemporary(req)

	for _, c := range n.cookies {
		req.Header.SetCookieBytesKV(c.Key(), c.Value())
	}

	err = nil

	if n.followRedirects && n.useCookies {
		err = n.doCookieWithRedirects(req, resp)
	} else if n.followRedirects && !n.useCookies {
		err = n.client.DoRedirects(req, resp, 10)
	} else {
		err = n.client.Do(req, resp)
	}

	if err != nil {
		if strings.Contains(err.Error(), "EOF") {
			// n.Logger.Printf("eof err: %v\n", err)
			// n.Logger.Println("EOF err.")
			return n.Get(url)
		}
		if strings.Contains(err.Error(), "unexpected protocol") {
			// n.Logger.Printf("unprotocol err: %v\n", err)
			// n.Logger.Println("Protocol err.")
			return n.Get(url)
		}
		return response, err
	}

	response.StatusCode = resp.StatusCode()
	response.ResponseBody = string(resp.Body())
	response.Header = parseHeaders(resp.Header.String())

	// n.Logger.Println(resp.Header.String())

	resp.Header.VisitAllCookie(func(key, value []byte) {
		c := fasthttp.AcquireCookie()
		if n.useCookies == false {
			defer fasthttp.ReleaseCookie(c)
		}
		c.ParseBytes(value)

		n.cookies = append(n.cookies, c)
	})

	return response, err
}

//Post @
func (n *Navigator) Post(url string, contentType string, form url.Values) (response Response, err error) {
	resp, req := fasthttp.AcquireResponse(), fasthttp.AcquireRequest()
	defer func() {
		fasthttp.ReleaseResponse(resp)
		fasthttp.ReleaseRequest(req)
	}()

	req.Header.SetMethod("POST")
	req.Header.SetRequestURI(url)
	req.Header.SetContentType(contentType)
	req.Header.SetContentLength(len(form.Encode()))
	req.AppendBodyString(form.Encode())

	n.setUpTemporary(req)

	for _, c := range n.cookies {
		req.Header.SetCookieBytesKV(c.Key(), c.Value())
	}

	if n.followRedirects && n.useCookies {
		err = n.doCookieWithRedirects(req, resp)
	} else if n.followRedirects && !n.useCookies {
		err = n.client.DoRedirects(req, resp, 10)
	} else {
		err = n.client.Do(req, resp)
	}

	if err != nil {
		if strings.Contains(err.Error(), "EOF") {
			// n.Logger.Printf("eof err: %#+v\n", err)
			// n.Logger.Println("requesting new", url)
			return n.Post(url, contentType, form)
		}
		if strings.Contains(err.Error(), "unexpected protocol") {
			// n.Logger.Printf("unprotocol err: %#+v\n", err)
			// n.Logger.Println("requesting new", url)
			return n.Post(url, contentType, form)
		}
		return response, err
	}

	response.StatusCode = resp.StatusCode()
	response.ResponseBody = string(resp.Body())
	response.Header = parseHeaders(resp.Header.String())

	resp.Header.VisitAllCookie(func(key, value []byte) {
		c := fasthttp.AcquireCookie()
		if n.useCookies == false {
			defer fasthttp.ReleaseCookie(c)
		}
		c.ParseBytes(value)

		n.cookies = append(n.cookies, c)
	})

	return response, err
}

func (n *Navigator) doCookieWithRedirects(req *fasthttp.Request, resp *fasthttp.Response) error {
	for {
		if err := n.client.Do(req, resp); err != nil {
			return err
		}

		statusCode := resp.Header.StatusCode()
		if statusCode != fasthttp.StatusMovedPermanently &&
			statusCode != fasthttp.StatusFound &&
			statusCode != fasthttp.StatusSeeOther &&
			statusCode != fasthttp.StatusTemporaryRedirect &&
			statusCode != fasthttp.StatusPermanentRedirect {
			break
		}

		location := resp.Header.PeekBytes([]byte("Location"))
		if len(location) == 0 {
			return fmt.Errorf("Redirect with missing Location header")
		}

		u := req.URI()
		u.UpdateBytes(location)

		resp.Header.VisitAllCookie(func(key, value []byte) {
			c := fasthttp.AcquireCookie()
			if n.useCookies == false {
				defer fasthttp.ReleaseCookie(c)
			}
			c.ParseBytes(value)

			n.cookies = append(n.cookies, c)
			if expire := c.Expire(); expire != fasthttp.CookieExpireUnlimited && expire.Before(time.Now()) {
				req.Header.DelCookieBytes(key)
			} else {
				req.Header.SetCookieBytesKV(key, c.Value())
			}
		})
	}

	return nil
}
