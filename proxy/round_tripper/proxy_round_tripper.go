package round_tripper

import (
	"errors"
	"io/ioutil"
	"net"
	"net/http"

	"github.com/uber-go/zap"

	"code.cloudfoundry.org/gorouter/logger"
	"code.cloudfoundry.org/gorouter/proxy/handler"
	"code.cloudfoundry.org/gorouter/route"
)

const (
	VcapCookieId    = "__VCAP_ID__"
	StickyCookieKey = "JSESSIONID"
)

type AfterRoundTrip func(req *http.Request, rsp *http.Response, endpoint *route.Endpoint, err error)

func NewProxyRoundTripper(
	transport http.RoundTripper,
	logger logger.Logger,
	afterRoundTrip AfterRoundTrip,
	defaultLoadBalance string,
) http.RoundTripper {
	return &RoundTripper{
		logger:             logger,
		transport:          transport,
		after:              afterRoundTrip,
		defaultLoadBalance: defaultLoadBalance,
	}
}

type RoundTripper struct {
	transport          http.RoundTripper
	logger             logger.Logger
	after              AfterRoundTrip
	defaultLoadBalance string
}

func (rt *RoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
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

	if rt.after != nil {
		rt.after(request, res, endpoint, err)
	}

	return res, err
}

func (rt *RoundTripper) selectEndpoint(iter route.EndpointIterator, request *http.Request) (*route.Endpoint, error) {
	endpoint := iter.Next()
	if endpoint == nil {
		return nil, handler.NoEndpointsAvailable
	}

	rt.logger = rt.logger.With(zap.Nest("route-endpoint", endpoint.ToLogData()...))
	return endpoint, nil
}

func (rt *RoundTripper) setupRequest(request *http.Request, endpoint *route.Endpoint) {
	rt.logger.Debug("backend")
	request.URL.Host = endpoint.CanonicalAddr()
	request.Header.Set("X-CF-ApplicationID", endpoint.ApplicationId)
	handler.SetRequestXCfInstanceId(request, endpoint)
}

func (rt *RoundTripper) reportError(iter route.EndpointIterator, err error) {
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
	if netErr && ne.Op == "dial" {
		return true
	}

	return false
}

func newRouteServiceEndpoint() *route.Endpoint {
	return &route.Endpoint{
		Tags: map[string]string{},
	}
}
