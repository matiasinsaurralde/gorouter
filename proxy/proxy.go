package proxy

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"

	"code.cloudfoundry.org/gorouter/access_log"
	"code.cloudfoundry.org/gorouter/access_log/schema"
	router_http "code.cloudfoundry.org/gorouter/common/http"
	"code.cloudfoundry.org/gorouter/config"
	"code.cloudfoundry.org/gorouter/handlers"
	"code.cloudfoundry.org/gorouter/logger"
	"code.cloudfoundry.org/gorouter/metrics"
	"code.cloudfoundry.org/gorouter/proxy/handler"
	"code.cloudfoundry.org/gorouter/proxy/round_tripper"
	"code.cloudfoundry.org/gorouter/proxy/utils"
	"code.cloudfoundry.org/gorouter/registry"
	"code.cloudfoundry.org/gorouter/route"
	"code.cloudfoundry.org/gorouter/routeservice"
	"github.com/uber-go/zap"
	"github.com/urfave/negroni"
)

const (
	VcapCookieId    = "__VCAP_ID__"
	StickyCookieKey = "JSESSIONID"
)

type Proxy interface {
	ServeHTTP(responseWriter http.ResponseWriter, request *http.Request)
}

type proxy struct {
	ip                       string
	traceKey                 string
	logger                   logger.Logger
	reporter                 metrics.CombinedReporter
	accessLogger             access_log.AccessLogger
	secureCookies            bool
	heartbeatOK              *int32
	routeServiceConfig       *routeservice.RouteServiceConfig
	healthCheckUserAgent     string
	forceForwardedProtoHttps bool
	defaultLoadBalance       string
	bufferPool               httputil.BufferPool
}

func NewProxy(
	logger logger.Logger,
	accessLogger access_log.AccessLogger,
	c *config.Config,
	registry registry.Registry,
	reporter metrics.CombinedReporter,
	routeServiceConfig *routeservice.RouteServiceConfig,
	tlsConfig *tls.Config,
	heartbeatOK *int32,
) Proxy {

	p := &proxy{
		accessLogger:             accessLogger,
		traceKey:                 c.TraceKey,
		ip:                       c.Ip,
		logger:                   logger,
		reporter:                 reporter,
		secureCookies:            c.SecureCookies,
		heartbeatOK:              heartbeatOK, // 1->true, 0->false
		routeServiceConfig:       routeServiceConfig,
		healthCheckUserAgent:     c.HealthCheckUserAgent,
		forceForwardedProtoHttps: c.ForceForwardedProtoHttps,
		defaultLoadBalance:       c.LoadBalance,
		bufferPool:               NewBufferPool(),
	}

	httpTransport := &http.Transport{
		Dial: func(network, addr string) (net.Conn, error) {
			conn, err := net.DialTimeout(network, addr, 5*time.Second)
			if err != nil {
				return conn, err
			}
			if c.EndpointTimeout > 0 {
				err = conn.SetDeadline(time.Now().Add(c.EndpointTimeout))
			}
			return conn, err
		},
		DisableKeepAlives:   c.DisableKeepAlives,
		MaxIdleConns:        c.MaxIdleConns,
		IdleConnTimeout:     90 * time.Second, // setting the value to golang default transport
		MaxIdleConnsPerHost: c.MaxIdleConnsPerHost,
		DisableCompression:  true,
		TLSClientConfig:     tlsConfig,
	}

	rproxy := &ReverseProxy{
		Director:       p.setupProxyRequest,
		Transport:      p.proxyRoundTripper(httpTransport, c.Port),
		FlushInterval:  50 * time.Millisecond,
		BufferPool:     p.bufferPool,
		ModifyResponse: p.modifyResponse,
	}

	zipkinHandler := handlers.NewZipkin(c.Tracing.EnableZipkin, c.ExtraHeadersToLog, logger)
	n := negroni.New()
	n.Use(handlers.NewProxyWriter())
	n.Use(handlers.NewsetVcapRequestIdHeader(logger))
	n.Use(handlers.NewAccessLog(accessLogger, zipkinHandler.HeadersToLog()))

	n.Use(handlers.NewProxyHealthcheck(c.HealthCheckUserAgent, p.heartbeatOK, logger))
	n.Use(zipkinHandler)
	n.Use(handlers.NewProtocolCheck(logger))
	n.Use(handlers.NewLookup(registry, reporter, logger))
	n.Use(handlers.NewRouteService(routeServiceConfig, logger, registry))
	n.Use(p)
	n.UseHandler(rproxy)

	return n
}

func hostWithoutPort(req *http.Request) string {
	host := req.Host

	// Remove :<port>
	pos := strings.Index(host, ":")
	if pos >= 0 {
		host = host[0:pos]
	}

	return host
}

func (p *proxy) proxyRoundTripper(transport round_tripper.ProxyRoundTripper, port uint16) round_tripper.ProxyRoundTripper {
	return round_tripper.NewProxyRoundTripper(
		round_tripper.NewDropsondeRoundTripper(transport),
		p.logger, p.traceKey, p.ip, p.defaultLoadBalance,
		p.reporter, p.secureCookies,
		port,
	)
}

type bufferPool struct {
	pool *sync.Pool
}

func NewBufferPool() httputil.BufferPool {
	return &bufferPool{
		pool: new(sync.Pool),
	}
}

func (b *bufferPool) Get() []byte {
	buf := b.pool.Get()
	if buf == nil {
		return make([]byte, 8192)
	}
	return buf.([]byte)
}

func (b *bufferPool) Put(buf []byte) {
	b.pool.Put(buf)
}

func (p *proxy) ServeHTTP(responseWriter http.ResponseWriter, request *http.Request, next http.HandlerFunc) {
	proxyWriter := responseWriter.(utils.ProxyResponseWriter)

	alr := request.Context().Value("AccessLogRecord")
	if alr == nil {
		p.logger.Error("AccessLogRecord not set on context", zap.Error(errors.New("failed-to-access-LogRecord")))
		http.Error(responseWriter, "AccessLogRecord not set on context", http.StatusInternalServerError)
		return
	}
	accessLog := alr.(*schema.AccessLogRecord)
	handler := handler.NewRequestHandler(request, proxyWriter, p.reporter, accessLog, p.logger)

	rp := request.Context().Value("RoutePool")
	if rp == nil {
		p.logger.Error("RoutePool not set on context", zap.Error(errors.New("failed-to-access-RoutePool")))
		http.Error(responseWriter, "RoutePool not set on context", http.StatusInternalServerError)
		return
	}
	routePool := rp.(*route.Pool)

	stickyEndpointId := getStickySession(request)
	iter := &wrappedIterator{
		nested: routePool.Endpoints(p.defaultLoadBalance, stickyEndpointId),

		afterNext: func(endpoint *route.Endpoint) {
			if endpoint != nil {
				accessLog.RouteEndpoint = endpoint
				p.reporter.CaptureRoutingRequest(endpoint)
			}
		},
	}

	if isTcpUpgrade(request) {
		handler.HandleTcpRequest(iter)
		return
	}

	if isWebSocketUpgrade(request) {
		handler.HandleWebSocketRequest(iter)
		return
	}

	next(responseWriter, request)
}

func (p *proxy) setupProxyRequest(target *http.Request) {
	if p.forceForwardedProtoHttps {
		target.Header.Set("X-Forwarded-Proto", "https")
	} else if target.Header.Get("X-Forwarded-Proto") == "" {
		scheme := "http"
		if target.TLS != nil {
			scheme = "https"
		}
		target.Header.Set("X-Forwarded-Proto", scheme)
	}

	target.URL.Scheme = "http"
	target.URL.Host = target.Host
	target.URL.Opaque = target.RequestURI
	target.URL.RawQuery = ""
	target.URL.ForceQuery = false

	handler.SetRequestXRequestStart(target)
	target.Header.Del(router_http.CfAppInstance)
}

func (p *proxy) modifyResponse(backendResp *http.Response) error {
	return nil
}

type wrappedIterator struct {
	nested    route.EndpointIterator
	afterNext func(*route.Endpoint)
}

func (i *wrappedIterator) Next() *route.Endpoint {
	e := i.nested.Next()
	if i.afterNext != nil {
		i.afterNext(e)
	}
	return e
}

func (i *wrappedIterator) EndpointFailed() {
	i.nested.EndpointFailed()
}
func (i *wrappedIterator) PreRequest(e *route.Endpoint) {
	i.nested.PreRequest(e)
}
func (i *wrappedIterator) PostRequest(e *route.Endpoint) {
	i.nested.PostRequest(e)
}

func getStickySession(request *http.Request) string {
	// Try choosing a backend using sticky session
	if _, err := request.Cookie(StickyCookieKey); err == nil {
		if sticky, err := request.Cookie(VcapCookieId); err == nil {
			return sticky.Value
		}
	}
	return ""
}

func isWebSocketUpgrade(request *http.Request) bool {
	// websocket should be case insensitive per RFC6455 4.2.1
	return strings.ToLower(upgradeHeader(request)) == "websocket"
}

func isTcpUpgrade(request *http.Request) bool {
	return upgradeHeader(request) == "tcp"
}

func upgradeHeader(request *http.Request) string {
	// handle multiple Connection field-values, either in a comma-separated string or multiple field-headers
	for _, v := range request.Header[http.CanonicalHeaderKey("Connection")] {
		// upgrade should be case insensitive per RFC6455 4.2.1
		if strings.Contains(strings.ToLower(v), "upgrade") {
			return request.Header.Get("Upgrade")
		}
	}

	return ""
}
