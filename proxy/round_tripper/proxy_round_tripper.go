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
) ProxyRoundTripper {
	return &roundTripper{
		logger:             logger,
		transport:          transport,
		traceKey:           traceKey,
		routerIP:           routerIP,
		defaultLoadBalance: defaultLoadBalance,
		combinedReporter:   combinedReporter,
	}
}

type roundTripper struct {
	transport          ProxyRoundTripper
	logger             logger.Logger
	traceKey           string
	routerIP           string
	defaultLoadBalance string
	combinedReporter   metrics.CombinedReporter
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

	routePool := rp.(*route.Pool)
	stickyEndpointId := getStickySession(request)
	iter := routePool.Endpoints(rt.defaultLoadBalance, stickyEndpointId)
	for retry := 0; retry < handler.MaxRetries; retry++ {
		endpoint, err = rt.selectEndpoint(iter, request)
		if err != nil {
			break
		}

		rt.setupRequest(request, endpoint)

		// increment connection stats
		iter.PreRequest(endpoint)

		rt.combinedReporter.CaptureRoutingRequest(endpoint)
		res, err = rt.transport.RoundTrip(request)

		// decrement connection stats
		iter.PostRequest(endpoint)

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

	return res, nil
}

func (rt *roundTripper) CancelRequest(request *http.Request) {
	rt.transport.CancelRequest(request)
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

// func newRouteServiceEndpoint() *route.Endpoint {
// 	return &route.Endpoint{
// 		Tags: map[string]string{},
// 	}
// }
