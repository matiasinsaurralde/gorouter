package round_tripper

import (
	"errors"
	"io/ioutil"
	"net"
	"net/http"

	"github.com/uber-go/zap"

	"code.cloudfoundry.org/gorouter/access_log/schema"
	router_http "code.cloudfoundry.org/gorouter/common/http"
	"code.cloudfoundry.org/gorouter/handlers"
	"code.cloudfoundry.org/gorouter/logger"
	"code.cloudfoundry.org/gorouter/metrics"
	"code.cloudfoundry.org/gorouter/proxy/handler"
	"code.cloudfoundry.org/gorouter/proxy/utils"
	"code.cloudfoundry.org/gorouter/route"
)

const (
	VcapCookieId      = "__VCAP_ID__"
	StickyCookieKey   = "JSESSIONID"
	BadGatewayMessage = "502 Bad Gateway: Registered endpoint failed to handle the request."
)

//go:generate counterfeiter -o fakes/fake_proxy_round_tripper.go . ProxyRoundTripper
type ProxyRoundTripper interface {
	http.RoundTripper
	CancelRequest(*http.Request)
}

type AfterRoundTrip func(req *http.Request, rsp *http.Response, endpoint *route.Endpoint, err error)

func NewProxyRoundTripper(
	transport ProxyRoundTripper,
	logger logger.Logger,
	traceKey string,
	routerIP string,
	defaultLoadBalance string,
	combinedReporter metrics.CombinedReporter,
	secureCookies bool,
) ProxyRoundTripper {
	return &roundTripper{
		logger:             logger,
		transport:          transport,
		traceKey:           traceKey,
		routerIP:           routerIP,
		defaultLoadBalance: defaultLoadBalance,
		combinedReporter:   combinedReporter,
		secureCookies:      secureCookies,
	}
}

type roundTripper struct {
	transport          ProxyRoundTripper
	logger             logger.Logger
	traceKey           string
	routerIP           string
	defaultLoadBalance string
	combinedReporter   metrics.CombinedReporter
	secureCookies      bool
}

func (rt *roundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	var err error
	var res *http.Response
	var endpoint *route.Endpoint

	if request.Body != nil {
		closer := request.Body
		request.Body = ioutil.NopCloser(request.Body)
		defer func() {
			closer.Close()
		}()
	}

	rp := request.Context().Value("RoutePool")
	if rp == nil {
		return nil, errors.New("RoutePool not set on context")
	}

	rw := request.Context().Value(handlers.ProxyResponseWriterCtxKey)
	if rw == nil {
		return nil, errors.New("ProxyResponseWriter not set on context")
	}

	alr := request.Context().Value("AccessLogRecord")
	if alr == nil {
		return nil, errors.New("AccessLogRecord not set on context")
	}
	accessLogRecord := alr.(*schema.AccessLogRecord)

	var routeServiceURL string
	rsurl := request.Context().Value("RouteServiceURL")
	if rsurl != nil {
		routeServiceURL = rsurl.(string)
	}

	routePool := rp.(*route.Pool)
	stickyEndpointID := getStickySession(request)
	iter := routePool.Endpoints(rt.defaultLoadBalance, stickyEndpointID)
	for retry := 0; retry < handler.MaxRetries; retry++ {

		if routeServiceURL == "" {
			endpoint, err = rt.selectEndpoint(iter, request)
			if err != nil {
				break
			}
			res, err = rt.backendRoundTrip(request, endpoint, iter)
		} else {
			rt.logger.Debug("route-service")
			endpoint = newRouteServiceEndpoint()
			request.URL.Host = routeServiceURL
			res, err = rt.transport.RoundTrip(request)
		}

		if err == nil || !retryableError(err) {
			break
		}

		rt.reportError(iter, err)
	}

	accessLogRecord.RouteEndpoint = endpoint

	if err != nil {
		responseWriter := rw.(utils.ProxyResponseWriter)
		responseWriter.Header().Set(router_http.CfRouterError, "endpoint_failure")

		accessLogRecord.StatusCode = http.StatusBadGateway

		rt.logger.Info("status", zap.String("body", BadGatewayMessage))

		http.Error(responseWriter, BadGatewayMessage, http.StatusBadGateway)
		responseWriter.Header().Del("Connection")

		rt.logger.Error("endpoint-failed", zap.Error(err))

		rt.combinedReporter.CaptureBadGateway()

		responseWriter.Done()

		return nil, err
	}

	if rt.traceKey != "" && request.Header.Get(router_http.VcapTraceHeader) == rt.traceKey {
		if res != nil && endpoint != nil {
			res.Header.Set(router_http.VcapRouterHeader, rt.routerIP)
			res.Header.Set(router_http.VcapBackendHeader, endpoint.CanonicalAddr())
			res.Header.Set(router_http.CfRouteEndpointHeader, endpoint.CanonicalAddr())
		}
	}

	if res != nil && endpoint.PrivateInstanceId != "" {
		setupStickySession(res, endpoint, stickyEndpointID, rt.secureCookies, routePool.ContextPath())
	}

	return res, nil
}

func (rt *roundTripper) CancelRequest(request *http.Request) {
	rt.transport.CancelRequest(request)
}

func (rt *roundTripper) backendRoundTrip(
	request *http.Request,
	endpoint *route.Endpoint,
	iter route.EndpointIterator,
) (*http.Response, error) {
	rt.setupRequest(request, endpoint)

	// increment connection stats
	iter.PreRequest(endpoint)

	rt.combinedReporter.CaptureRoutingRequest(endpoint)
	res, err := rt.transport.RoundTrip(request)

	// decrement connection stats
	iter.PostRequest(endpoint)
	return res, err
}

func (rt *roundTripper) selectEndpoint(iter route.EndpointIterator, request *http.Request) (*route.Endpoint, error) {
	endpoint := iter.Next()
	if endpoint == nil {
		return nil, handler.NoEndpointsAvailable
	}

	rt.logger = rt.logger.With(zap.Nest("route-endpoint", endpoint.ToLogData()...))
	return endpoint, nil
}

func (rt *roundTripper) setupRequest(request *http.Request, endpoint *route.Endpoint) {
	rt.logger.Debug("backend")
	request.URL.Host = endpoint.CanonicalAddr()
	request.Header.Set("X-CF-ApplicationID", endpoint.ApplicationId)
	handler.SetRequestXCfInstanceId(request, endpoint)
}

func (rt *roundTripper) reportError(iter route.EndpointIterator, err error) {
	iter.EndpointFailed()
	rt.logger.Error("backend-endpoint-failed", zap.Error(err))
}

func setupStickySession(
	response *http.Response,
	endpoint *route.Endpoint,
	originalEndpointId string,
	secureCookies bool,
	path string,
) {
	secure := false
	maxAge := 0

	// did the endpoint change?
	sticky := originalEndpointId != "" && originalEndpointId != endpoint.PrivateInstanceId

	for _, v := range response.Cookies() {
		if v.Name == StickyCookieKey {
			sticky = true
			if v.MaxAge < 0 {
				maxAge = v.MaxAge
			}
			secure = v.Secure
			break
		}
	}

	if sticky {
		// right now secure attribute would as equal to the JSESSION ID cookie (if present),
		// but override if set to true in config
		if secureCookies {
			secure = true
		}

		cookie := &http.Cookie{
			Name:     VcapCookieId,
			Value:    endpoint.PrivateInstanceId,
			Path:     path,
			MaxAge:   maxAge,
			HttpOnly: true,
			Secure:   secure,
		}

		if v := cookie.String(); v != "" {
			response.Header.Add("Set-Cookie", v)
		}
	}
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

func retryableError(err error) bool {
	ne, netErr := err.(*net.OpError)
	if netErr && (ne.Op == "dial" || ne.Op == "read" && ne.Err.Error() == "read: connection reset by peer") {
		return true
	}
	return false
}

func newRouteServiceEndpoint() *route.Endpoint {
	return &route.Endpoint{
		Tags: map[string]string{},
	}
}
