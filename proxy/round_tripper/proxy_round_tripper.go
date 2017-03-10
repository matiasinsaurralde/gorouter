package round_tripper

import (
	"errors"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	"github.com/uber-go/zap"

	"code.cloudfoundry.org/gorouter/logger"
	"code.cloudfoundry.org/gorouter/proxy/handler"
	"code.cloudfoundry.org/gorouter/route"
	"golang.org/x/tools/go/gcimporter15/testdata"
)

const (
	VcapCookieId    = "__VCAP_ID__"
	StickyCookieKey = "JSESSIONID"
)

//go:generate counterfeiter -o fakes/fake_proxy_round_tripper.go . RoundTripper
type RoundTripper interface {
	http.RoundTripper
	CancelRequest(*http.Request)
}

type AfterRoundTrip func(req *http.Request, rsp *http.Response, endpoint *route.Endpoint, err error)

func NewProxyRoundTripper(
	transport RoundTripper,
	logger logger.Logger,
	defaultLoadBalance string,
) RoundTripper {
	return &roundTripper{
		logger:             logger,
		transport:          transport,
		defaultLoadBalance: defaultLoadBalance,
	}
}

type roundTripper struct {
	transport          RoundTripper
	logger             logger.Logger
	defaultLoadBalance string
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

		res, err = rt.transport.RoundTrip(request)

		// decrement connection stats
		iter.PostRequest(endpoint)

		if err == nil || !retryableError(err) {
			break
		}

		rt.reportError(iter, err)
	}

	if err != nil {
		rt.logger.Error("endpoint-failed", zap.Error(err))
	}

	after(request, res, endpoint, err)

	return res, err
}

func after(request, *http.Request, rsp *http.Response, endpoint *route.Endpoint, err error) {
	if endpoint == nil {
		handler.HandleBadGateway(err, request)
		return
	}

	accessLog.FirstByteAt = time.Now()
	if rsp != nil {
		accessLog.StatusCode = rsp.StatusCode
	}

	if p.traceKey != "" && endpoint != nil && request.Header.Get(router_http.VcapTraceHeader) == p.traceKey {
		router_http.SetTraceHeaders(responseWriter, p.ip, endpoint.CanonicalAddr())
	}

	latency := time.Since(accessLog.StartedAt)


		p.reporter.CaptureRoutingResponse(rsp)
		p.reporter.CaptureRoutingResponseLatency(endpoint, rsp, accessLog.StartedAt, latency)


	if err != nil {
		handler.HandleBadGateway(err, request)
		return
	}

	if endpoint.PrivateInstanceId != "" {
		setupStickySession(responseWriter, rsp, endpoint, stickyEndpointId, p.secureCookies, routePool.ContextPath())
	}

	// if Content-Type not in response, nil out to suppress Go's auto-detect
	if _, ok := rsp.Header["Content-Type"]; !ok {
		responseWriter.Header()["Content-Type"] = nil
	}
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

func newRouteServiceEndpoint() *route.Endpoint {
	return &route.Endpoint{
		Tags: map[string]string{},
	}
}
