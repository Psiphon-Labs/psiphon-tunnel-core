package upstreamproxy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type ProxyAuthTransport struct {
	*http.Transport
	Dial     DialFunc
	Username string
	Password string
}

func NewProxyAuthTransport(proxy string, dialFn DialFunc, responseHeaderTimeout time.Duration) (*ProxyAuthTransport, error) {
	tr := &ProxyAuthTransport{Dial: dialFn}

	wrappedDialFn := tr.wrapTransportDial()
	proxyUrl, err := url.Parse(proxy)
	if err != nil {
		return nil, err
	}
	tr.Username = proxyUrl.User.Username()
	tr.Password, _ = proxyUrl.User.Password()
	tr.Transport = &http.Transport{
		Dial:  wrappedDialFn,
		Proxy: http.ProxyURL(proxyUrl),
		ResponseHeaderTimeout: responseHeaderTimeout,
	}
	return tr, nil
}

func (tr *ProxyAuthTransport) wrapTransportDial() DialFunc {
	return func(network, addr string) (net.Conn, error) {
		c, err := tr.Dial("tcp", addr)
		if err != nil {
			return nil, err
		}
		tc := newTransportConn(c, tr.Dial, tr)
		return tc, nil
	}
}

type transportConn struct {
	net.Conn
	requestWriter io.Writer
	reqDone       chan struct{}
	connReader    *bufio.Reader
	lastRequest   *http.Request
	Dial          DialFunc
	authenticator HttpAuthenticator
	authState     HttpAuthState
	transport     *ProxyAuthTransport
}

func newTransportConn(c net.Conn, dialFn DialFunc, tr *ProxyAuthTransport) *transportConn {
	tc := &transportConn{
		Conn:       c,
		reqDone:    make(chan struct{}),
		connReader: bufio.NewReader(c),
		Dial:       dialFn,
		transport:  tr,
	}
	go func() {
		pr, pw := io.Pipe()
		defer pr.Close()
		defer pw.Close()
		tc.requestWriter = pw
		for {
			//Request intercepting loop
			req, err := http.ReadRequest(bufio.NewReader(pr))
			if err != nil {
				fmt.Println("http.ReadRequest error: ", err)
			}
			//read and copy entire body
			body, _ := ioutil.ReadAll(req.Body)
			tc.lastRequest = req
			tc.lastRequest.Body = ioutil.NopCloser(bytes.NewReader(body))
			tc.reqDone <- struct{}{}
		}
	}()
	return tc
}

func (tc *transportConn) Read(p []byte) (int, error) {
	/*
	   The first Read on a new RoundTrip will occur *before* Write and
	   will block until request is written out completely and response
	   headers are read in

	   Peek will actually call Read and buffer read data
	*/
	peeked, err := tc.connReader.Peek(12)
	if err != nil {
		return 0, err
	}
	line := string(peeked)
	select {
	case _ = <-tc.reqDone:
		//Brand new response
		f := strings.SplitN(line, " ", 2)
		if (f[0] == "HTTP/1.0" || f[0] == "HTTP/1.1") && f[1] == "407" {
			resp, err := http.ReadResponse(tc.connReader, nil)
			if err != nil {
				return 0, err
			}
			// make sure we read the body of the response so that
			// we don't block the reader
			ioutil.ReadAll(resp.Body)
			resp.Body.Close()

			if tc.authState == HTTP_AUTH_STATE_UNCHALLENGED {
				tc.authenticator, err = NewHttpAuthenticator(resp)
				if err != nil {
					return 0, err
				}
				tc.authState = HTTP_AUTH_STATE_CHALLENGED
			}

			if resp.Close == true {
				// Server side indicated that it is closing this connection,
				// dial a new one
				addr := tc.Conn.RemoteAddr()
				tc.Conn.Close()
				tc.Conn, err = tc.Dial(addr.Network(), addr.String())
				if err != nil {
					return 0, err
				}
			}

			err = tc.authenticator.Authenticate(tc.lastRequest, resp, tc.transport.Username, tc.transport.Password)
			if err != nil {
				return 0, err
			}

			//TODO: eliminate possible race condition
			//Replay authenticated request
			tc.lastRequest.WriteProxy(tc)
			return tc.Read(p)
		}
	default:
	}
	n, err := tc.connReader.Read(p)
	return n, err
}

func (tc *transportConn) Write(p []byte) (n int, err error) {
	n, err = tc.Conn.Write(p)
	tc.requestWriter.Write(p[:n])
	return n, err
}
