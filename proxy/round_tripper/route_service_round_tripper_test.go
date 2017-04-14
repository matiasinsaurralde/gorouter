package round_tripper_test

import (
	"context"
	"errors"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"time"

	"code.cloudfoundry.org/gorouter/access_log/schema"
	"code.cloudfoundry.org/gorouter/handlers"
	"code.cloudfoundry.org/gorouter/metrics/fakes"
	"code.cloudfoundry.org/gorouter/proxy/round_tripper"
	roundtripperfakes "code.cloudfoundry.org/gorouter/proxy/round_tripper/fakes"
	"code.cloudfoundry.org/gorouter/proxy/utils"
	"code.cloudfoundry.org/gorouter/route"
	"code.cloudfoundry.org/gorouter/test_util"
	"code.cloudfoundry.org/routing-api/models"

	router_http "code.cloudfoundry.org/gorouter/common/http"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
)

var _ = Describe("RouteServiceRoundTripper", func() {
	var (
		routeServiceRoundTripper round_tripper.ProxyRoundTripper
		routePool                *route.Pool
		transport                *roundtripperfakes.FakeProxyRoundTripper
		logger                   *test_util.TestZapLogger
		req                      *http.Request
		resp                     *httptest.ResponseRecorder
		alr                      *schema.AccessLogRecord
		routerIP                 string
		combinedReporter         *fakes.FakeCombinedReporter

		endpoint *route.Endpoint

		routeServiceURL *url.URL

		dialError = &net.OpError{
			Err: errors.New("error"),
			Op:  "dial",
		}
	)

	BeforeEach(func() {
		routePool = route.NewPool(1*time.Second, "")
		resp = httptest.NewRecorder()
		resp.Header().Add("Connection", "fake-connection")
		alr = &schema.AccessLogRecord{}
		proxyWriter := utils.NewProxyResponseWriter(resp)
		req = test_util.NewRequest("GET", "myapp.com", "/", nil)
		req.URL.Scheme = "http"

		req = req.WithContext(context.WithValue(req.Context(), "RoutePool", routePool))
		req = req.WithContext(context.WithValue(req.Context(), handlers.ProxyResponseWriterCtxKey, proxyWriter))
		req = req.WithContext(context.WithValue(req.Context(), "AccessLogRecord", alr))

		logger = test_util.NewTestZapLogger("test")
		transport = new(roundtripperfakes.FakeProxyRoundTripper)
		routerIP = "127.0.0.1"

		endpoint = route.NewEndpoint("appId", "1.1.1.1", uint16(9090), "id", "1",
			map[string]string{}, 0, "", models.ModificationTag{})

		added := routePool.Put(endpoint)
		Expect(added).To(BeTrue())

		combinedReporter = new(fakes.FakeCombinedReporter)

		routeServiceRoundTripper = round_tripper.NewRouteServiceRoundTripper(
			transport, logger, "my_trace_key", routerIP, "",
			combinedReporter, false,
		)

		var err error
		routeServiceURL, err = url.Parse("https://foo.com")
		Expect(err).ToNot(HaveOccurred())

		req = req.WithContext(context.WithValue(req.Context(), handlers.RouteServiceURLCtxKey, routeServiceURL))
		transport.RoundTripStub = func(req *http.Request) (*http.Response, error) {
			Expect(req.Host).To(Equal(routeServiceURL.Host))
			Expect(req.URL).To(Equal(routeServiceURL))
			resp := &http.Response{StatusCode: http.StatusOK}
			return resp, nil
		}
	})

	Context("when proxy response writer is not set on the request context", func() {
		BeforeEach(func() {
			req = test_util.NewRequest("GET", "myapp.com", "/", nil)
			req = req.WithContext(context.WithValue(req.Context(), "RoutePool", routePool))
		})
		It("returns an error", func() {
			_, err := routeServiceRoundTripper.RoundTrip(req)
			Expect(err.Error()).To(ContainSubstring("ProxyResponseWriter not set on context"))
		})
	})

	Context("when access log record is not set on the request context", func() {
		BeforeEach(func() {
			req = test_util.NewRequest("GET", "myapp.com", "/", nil)
			req = req.WithContext(context.WithValue(req.Context(), "RoutePool", routePool))
			req = req.WithContext(context.WithValue(req.Context(), handlers.ProxyResponseWriterCtxKey, utils.NewProxyResponseWriter(resp)))
		})
		It("returns an error", func() {
			_, err := routeServiceRoundTripper.RoundTrip(req)
			Expect(err.Error()).To(ContainSubstring("AccessLogRecord not set on context"))
		})
	})

	Context("when the request to the route service is successful", func() {
		It("makes request to the route service and does not capture the routing request in metrics", func() {
			resp, err := routeServiceRoundTripper.RoundTrip(req)
			Expect(err).ToNot(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(http.StatusOK))

			Expect(combinedReporter.CaptureRoutingRequestCallCount()).To(Equal(0))
		})

		It("does not log an error", func() {
			resp, err := routeServiceRoundTripper.RoundTrip(req)
			Expect(err).ToNot(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(http.StatusOK))
			Expect(alr.StatusCode).ToNot(Equal(http.StatusBadGateway))

			Consistently(logger.Buffer()).ShouldNot(gbytes.Say("route-service-connection-failed"))

		})
	})

	Context("when the route service returns a non-2xx status code", func() {
		BeforeEach(func() {
			transport.RoundTripReturns(
				&http.Response{StatusCode: http.StatusTeapot}, nil,
			)

		})
		It("logs the response error", func() {
			_, err := routeServiceRoundTripper.RoundTrip(req)
			Expect(err).ToNot(HaveOccurred())

			Expect(logger.Buffer()).To(gbytes.Say(`response.*status-code":418`))
		})
	})

	Context("when the route service request fails", func() {
		BeforeEach(func() {
			transport.RoundTripReturns(
				nil, dialError,
			)
		})

		It("retries 3 times and returns status bad gateway", func() {
			_, err := routeServiceRoundTripper.RoundTrip(req)
			Expect(err).To(MatchError(dialError))
			Expect(transport.RoundTripCallCount()).To(Equal(3))

			Expect(resp.Code).To(Equal(http.StatusBadGateway))
			Expect(resp.Header().Get(router_http.CfRouterError)).To(Equal("endpoint_failure"))
			bodyBytes, err := ioutil.ReadAll(resp.Body)
			Expect(err).ToNot(HaveOccurred())
			Expect(string(bodyBytes)).To(ContainSubstring(round_tripper.BadGatewayMessage))
			Expect(alr.StatusCode).To(Equal(http.StatusBadGateway))
		})

		It("captures bad gateway response in the metrics reporter", func() {
			_, err := routeServiceRoundTripper.RoundTrip(req)
			Expect(err).To(MatchError(dialError))

			Expect(combinedReporter.CaptureBadGatewayCallCount()).To(Equal(1))
		})

		It("logs the failure", func() {
			_, err := routeServiceRoundTripper.RoundTrip(req)
			Expect(err).To(MatchError(dialError))

			for i := 0; i < 3; i++ {
				Expect(logger.Buffer()).To(gbytes.Say(`route-service-connection-failed.*dial`))
			}
		})

		It("deletes Connection header", func() {
			_, err := routeServiceRoundTripper.RoundTrip(req)
			Expect(err).To(HaveOccurred())
			Expect(resp.Header().Get("Connection")).To(Equal(""))
		})

		Context("when route service is unavailable due to non-retryable error", func() {
			BeforeEach(func() {
				transport.RoundTripReturns(nil, errors.New("error"))
			})

			It("does not retry and returns status bad gateway", func() {
				_, err := routeServiceRoundTripper.RoundTrip(req)
				Expect(err).To(MatchError(errors.New("error")))
				Expect(transport.RoundTripCallCount()).To(Equal(1))

				Expect(resp.Code).To(Equal(http.StatusBadGateway))
				Expect(resp.Header().Get(router_http.CfRouterError)).To(Equal("endpoint_failure"))
				bodyBytes, err := ioutil.ReadAll(resp.Body)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(bodyBytes)).To(ContainSubstring(round_tripper.BadGatewayMessage))
				Expect(alr.StatusCode).To(Equal(http.StatusBadGateway))
			})

			It("captures bad gateway response in the metrics reporter", func() {
				_, err := routeServiceRoundTripper.RoundTrip(req)
				Expect(err).To(MatchError(errors.New("error")))

				Expect(combinedReporter.CaptureBadGatewayCallCount()).To(Equal(1))
			})

			It("does not log the error or report the endpoint failure", func() {
				_, err := routeServiceRoundTripper.RoundTrip(req)
				Expect(err).To(MatchError(errors.New("error")))

				Expect(logger.Buffer()).ToNot(gbytes.Say(`route-service-connection-failed`))
			})
		})
	})

	It("can cancel requests", func() {
		routeServiceRoundTripper.CancelRequest(req)
		Expect(transport.CancelRequestCallCount()).To(Equal(1))
		Expect(transport.CancelRequestArgsForCall(0)).To(Equal(req))
	})
})
