package round_tripper

import (
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"

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

func NewRouteServiceRoundTripper(
	transport ProxyRoundTripper,
	logger logger.Logger,
	traceKey string,
	routerIP string,
	defaultLoadBalance string,
	combinedReporter metrics.CombinedReporter,
	secureCookies bool,
) ProxyRoundTripper {
	return &routeServiceRoundTripper{
		logger:             logger,
		transport:          transport,
		traceKey:           traceKey,
		routerIP:           routerIP,
		defaultLoadBalance: defaultLoadBalance,
		combinedReporter:   combinedReporter,
		secureCookies:      secureCookies,
	}
}

type routeServiceRoundTripper struct {
	transport          ProxyRoundTripper
	logger             logger.Logger
	traceKey           string
	routerIP           string
	defaultLoadBalance string
	combinedReporter   metrics.CombinedReporter
	secureCookies      bool
}

func (rt *routeServiceRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	var err error
	var res *http.Response

	if request.Body != nil {
		closer := request.Body
		request.Body = ioutil.NopCloser(request.Body)
		defer closer.Close()
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

	var routeServiceURL *url.URL
	rsurl := request.Context().Value(handlers.RouteServiceURLCtxKey)
	if rsurl != nil {
		routeServiceURL = rsurl.(*url.URL)
	}

	res, err = rt.sendRequest(request, routeServiceURL)

	if err == nil {
		if res != nil && (res.StatusCode < 200 || res.StatusCode >= 300) {
			rt.logger.Info(
				"route-service-response",
				zap.String("endpoint", request.URL.String()),
				zap.Int("status-code", res.StatusCode),
			)
		}
		return res, nil
	}

	responseWriter := rw.(utils.ProxyResponseWriter)
	defer responseWriter.Done()
	responseWriter.Header().Set(router_http.CfRouterError, "endpoint_failure")

	accessLogRecord.StatusCode = http.StatusBadGateway
	rt.logger.Info("status", zap.String("body", BadGatewayMessage))
	http.Error(responseWriter, BadGatewayMessage, http.StatusBadGateway)
	rt.logger.Error("endpoint-failed", zap.Error(err))

	rt.combinedReporter.CaptureBadGateway()

	responseWriter.Header().Del("Connection")

	return nil, err
}

func (rt *routeServiceRoundTripper) CancelRequest(request *http.Request) {
	rt.transport.CancelRequest(request)
}

func (rt *routeServiceRoundTripper) sendRequest(request *http.Request, routeServiceURL *url.URL) (*http.Response, error) {
	var err error
	var res *http.Response

	for retry := 0; retry < handler.MaxRetries; retry++ {

		rt.logger.Debug(
			"route-service",
			zap.Object("route-service-url", routeServiceURL),
			zap.Int("attempt", retry),
		)

		request.Host = routeServiceURL.Host
		request.URL = routeServiceURL
		res, err = rt.transport.RoundTrip(request)

		// this breaks us out if request was successful or if NOT a retryable error
		if !retryableError(err) {
			return res, err
		}
		rt.logger.Error("route-service-connection-failed", zap.Error(err))
	}
	return res, err
}

func newRouteServiceEndpoint() *route.Endpoint {
	return &route.Endpoint{
		Tags: map[string]string{},
	}
}
