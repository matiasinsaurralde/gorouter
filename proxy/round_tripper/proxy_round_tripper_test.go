package round_tripper_test

import (
	"context"
	"errors"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"syscall"
	"time"

	"code.cloudfoundry.org/gorouter/access_log/schema"
	"code.cloudfoundry.org/gorouter/handlers"
	"code.cloudfoundry.org/gorouter/logger"
	"code.cloudfoundry.org/gorouter/metrics/fakes"
	"code.cloudfoundry.org/gorouter/proxy/handler"
	"code.cloudfoundry.org/gorouter/proxy/round_tripper"
	roundtripperfakes "code.cloudfoundry.org/gorouter/proxy/round_tripper/fakes"
	"code.cloudfoundry.org/gorouter/proxy/utils"
	"code.cloudfoundry.org/gorouter/route"
	"code.cloudfoundry.org/gorouter/test_util"
	"code.cloudfoundry.org/routing-api/models"

	router_http "code.cloudfoundry.org/gorouter/common/http"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type nullVarz struct{}

var _ = Describe("ProxyRoundTripper", func() {
	Context("RoundTrip", func() {
		var (
			proxyRoundTripper round_tripper.ProxyRoundTripper
			routePool         *route.Pool
			transport         *roundtripperfakes.FakeProxyRoundTripper
			logger            logger.Logger
			req               *http.Request
			resp              *httptest.ResponseRecorder
			alr               *schema.AccessLogRecord
			routerIP          string
			combinedReporter  *fakes.FakeCombinedReporter

			endpoint *route.Endpoint

			dialError = &net.OpError{
				Err: errors.New("error"),
				Op:  "dial",
			}
			connResetError = &net.OpError{
				Err: os.NewSyscallError("read", syscall.ECONNRESET),
				Op:  "read",
			}
		)

		BeforeEach(func() {
			routePool = route.NewPool(1*time.Second, "")
			resp = httptest.NewRecorder()
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

			proxyRoundTripper = round_tripper.NewProxyRoundTripper(
				transport, logger, "my_trace_key", routerIP, "",
				combinedReporter, false,
			)
		})

		Context("when route pool is not set on the request context", func() {
			BeforeEach(func() {
				req = test_util.NewRequest("GET", "myapp.com", "/", nil)
			})
			It("returns an error", func() {
				_, err := proxyRoundTripper.RoundTrip(req)
				Expect(err.Error()).To(ContainSubstring("RoutePool not set on context"))
			})
		})

		Context("when proxy response writer is not set on the request context", func() {
			BeforeEach(func() {
				req = test_util.NewRequest("GET", "myapp.com", "/", nil)
				req = req.WithContext(context.WithValue(req.Context(), "RoutePool", routePool))
			})
			It("returns an error", func() {
				_, err := proxyRoundTripper.RoundTrip(req)
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
				_, err := proxyRoundTripper.RoundTrip(req)
				Expect(err.Error()).To(ContainSubstring("AccessLogRecord not set on context"))
			})
		})

		Context("VcapTraceHeader", func() {
			BeforeEach(func() {
				transport.RoundTripStub = func(req *http.Request) (*http.Response, error) {
					return resp.Result(), nil
				}
			})

			Context("when VcapTraceHeader matches the trace key", func() {
				BeforeEach(func() {
					req.Header.Set(router_http.VcapTraceHeader, "my_trace_key")
				})

				It("sets the trace headers on the response", func() {
					backendResp, err := proxyRoundTripper.RoundTrip(req)
					Expect(err).ToNot(HaveOccurred())

					Expect(backendResp.Header.Get(router_http.VcapRouterHeader)).To(Equal(routerIP))
					Expect(backendResp.Header.Get(router_http.VcapBackendHeader)).To(Equal("1.1.1.1:9090"))
					Expect(backendResp.Header.Get(router_http.VcapBackendHeader)).To(Equal("1.1.1.1:9090"))
				})
			})

			Context("when VcapTraceHeader does not match the trace key", func() {
				BeforeEach(func() {
					req.Header.Set(router_http.VcapTraceHeader, "not_my_trace_key")
				})
				It("does not set the trace headers on the response", func() {
					backendResp, err := proxyRoundTripper.RoundTrip(req)
					Expect(err).ToNot(HaveOccurred())

					Expect(backendResp.Header.Get(router_http.VcapRouterHeader)).To(Equal(""))
					Expect(backendResp.Header.Get(router_http.VcapBackendHeader)).To(Equal(""))
					Expect(backendResp.Header.Get(router_http.VcapBackendHeader)).To(Equal(""))
				})
			})

			Context("when VcapTraceHeader is not set", func() {
				It("does not set the trace headers on the response", func() {
					backendResp, err := proxyRoundTripper.RoundTrip(req)
					Expect(err).ToNot(HaveOccurred())

					Expect(backendResp.Header.Get(router_http.VcapRouterHeader)).To(Equal(""))
					Expect(backendResp.Header.Get(router_http.VcapBackendHeader)).To(Equal(""))
					Expect(backendResp.Header.Get(router_http.VcapBackendHeader)).To(Equal(""))
				})
			})
		})

		Context("when backend is unavailable due to dial error", func() {
			var retryCount int
			BeforeEach(func() {
				retryCount = 0
				transport.RoundTripStub = func(req *http.Request) (*http.Response, error) {
					retryCount++
					return nil, dialError
				}
			})

			It("retries 3 times and returns status bad gateway", func() {
				_, err := proxyRoundTripper.RoundTrip(req)
				Expect(err).To(MatchError(dialError))
				Expect(retryCount).To(Equal(3))

				Expect(resp.Code).To(Equal(http.StatusBadGateway))
				Expect(resp.Header().Get(router_http.CfRouterError)).To(Equal("endpoint_failure"))
				bodyBytes, err := ioutil.ReadAll(resp.Body)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(bodyBytes)).To(ContainSubstring(round_tripper.BadGatewayMessage))
				Expect(alr.StatusCode).To(Equal(http.StatusBadGateway))
				Expect(alr.RouteEndpoint).To(Equal(endpoint))
			})

			It("captures each routing request to the backend", func() {
				_, err := proxyRoundTripper.RoundTrip(req)
				Expect(err).To(MatchError(dialError))

				Expect(combinedReporter.CaptureRoutingRequestCallCount()).To(Equal(3))
				for i := 0; i < 3; i++ {
					Expect(combinedReporter.CaptureRoutingRequestArgsForCall(i)).To(Equal(endpoint))
				}
			})

			It("captures bad gateway response in the metrics reporter", func() {
				_, err := proxyRoundTripper.RoundTrip(req)
				Expect(err).To(MatchError(dialError))

				Expect(combinedReporter.CaptureBadGatewayCallCount()).To(Equal(1))
			})
		})

		Context("when backend is unavailable due to connection reset error", func() {
			var retryCount int
			BeforeEach(func() {
				retryCount = 0
				transport.RoundTripStub = func(req *http.Request) (*http.Response, error) {
					retryCount++
					return nil, connResetError
				}

				added := routePool.Put(endpoint)
				Expect(added).To(BeTrue())
			})

			It("retries 3 times", func() {
				_, err := proxyRoundTripper.RoundTrip(req)
				Expect(err).To(MatchError(connResetError))
				Expect(retryCount).To(Equal(3))

				Expect(resp.Code).To(Equal(http.StatusBadGateway))
				Expect(resp.Header().Get(router_http.CfRouterError)).To(Equal("endpoint_failure"))
				bodyBytes, err := ioutil.ReadAll(resp.Body)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(bodyBytes)).To(ContainSubstring(round_tripper.BadGatewayMessage))

				Expect(alr.StatusCode).To(Equal(http.StatusBadGateway))
				Expect(alr.RouteEndpoint).To(Equal(endpoint))
			})

			It("captures each routing request to the backend", func() {
				_, err := proxyRoundTripper.RoundTrip(req)
				Expect(err).To(MatchError(connResetError))

				Expect(combinedReporter.CaptureRoutingRequestCallCount()).To(Equal(3))
				for i := 0; i < 3; i++ {
					Expect(combinedReporter.CaptureRoutingRequestArgsForCall(i)).To(Equal(endpoint))
				}
			})

			It("captures bad gateway response in the metrics reporter", func() {
				_, err := proxyRoundTripper.RoundTrip(req)
				Expect(err).To(MatchError(connResetError))

				Expect(combinedReporter.CaptureBadGatewayCallCount()).To(Equal(1))
			})
		})

		Context("when there are no more endpoints available", func() {
			BeforeEach(func() {
				removed := routePool.Remove(endpoint)
				Expect(removed).To(BeTrue())
			})

			It("returns a 502 Bad Gateway response", func() {
				backendRes, err := proxyRoundTripper.RoundTrip(req)
				Expect(err).To(HaveOccurred())
				Expect(backendRes).To(BeNil())
				Expect(err).To(Equal(handler.NoEndpointsAvailable))

				Expect(resp.Code).To(Equal(http.StatusBadGateway))
				Expect(resp.Header().Get(router_http.CfRouterError)).To(Equal("endpoint_failure"))
				bodyBytes, err := ioutil.ReadAll(resp.Body)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(bodyBytes)).To(ContainSubstring(round_tripper.BadGatewayMessage))
				Expect(alr.StatusCode).To(Equal(http.StatusBadGateway))
				Expect(alr.RouteEndpoint).To(BeNil())
			})

			It("does not capture any routing requests to the backend", func() {
				_, err := proxyRoundTripper.RoundTrip(req)
				Expect(err).To(Equal(handler.NoEndpointsAvailable))

				Expect(combinedReporter.CaptureRoutingRequestCallCount()).To(Equal(0))
			})

			It("captures bad gateway response in the metrics reporter", func() {
				_, err := proxyRoundTripper.RoundTrip(req)
				Expect(err).To(Equal(handler.NoEndpointsAvailable))

				Expect(combinedReporter.CaptureBadGatewayCallCount()).To(Equal(1))
			})
		})

		Context("when the first request to the backend fails", func() {
			var retryCount int
			BeforeEach(func() {
				retryCount = 0
				transport.RoundTripStub = func(req *http.Request) (*http.Response, error) {
					var err error
					err = nil
					if retryCount == 0 {
						err = dialError
					}
					retryCount++
					return nil, err
				}
			})

			It("retries 2 times", func() {
				_, err := proxyRoundTripper.RoundTrip(req)
				Expect(err).ToNot(HaveOccurred())
				Expect(retryCount).To(Equal(2))
				Expect(resp.Code).To(Equal(http.StatusOK))

				Expect(combinedReporter.CaptureBadGatewayCallCount()).To(Equal(0))

				Expect(alr.RouteEndpoint).To(Equal(endpoint))
			})

			It("captures each routing request to the backend", func() {
				_, err := proxyRoundTripper.RoundTrip(req)
				Expect(err).ToNot(HaveOccurred())

				Expect(combinedReporter.CaptureRoutingRequestCallCount()).To(Equal(2))
				for i := 0; i < 2; i++ {
					Expect(combinedReporter.CaptureRoutingRequestArgsForCall(i)).To(Equal(endpoint))
				}
			})
		})

		It("can cancel requests", func() {
			proxyRoundTripper.CancelRequest(req)
			Expect(transport.CancelRequestCallCount()).To(Equal(1))
			Expect(transport.CancelRequestArgsForCall(0)).To(Equal(req))
		})

		// Context("route service", func() {
		// 	BeforeEach(func() {
		// 		endpoint := &route.Endpoint{
		// 			RouteServiceUrl: "https://routeservice.net/",
		// 			Tags:            map[string]string{},
		// 		}
		// 		// endpointIterator.NextReturns(endpoint)
		// 		req.Header.Set(routeservice.RouteServiceForwardedURL, "http://myapp.com/")
		//
		// 		after := func(req *http.Request, rsp *http.Response, endpoint *route.Endpoint, err error) {
		// 			Expect(endpoint.Tags).ShouldNot(BeNil())
		// 		}
		// 		proxyRoundTripper = round_tripper.NewProxyRoundTripper(transport, logger, after, "")
		// 	})
		//
		// 	FIt("does not fetch the next endpoint", func() {
		// 		_, err := proxyRoundTripper.RoundTrip(req)
		// 		Expect(err).NotTo(HaveOccurred())
		// 		// Expect(endpointIterator.NextCallCount()).To(Equal(0))
		// 	})
		//
		// 	It("can cancel requests", func() {
		// 		proxyRoundTripper.CancelRequest(req)
		// 		Expect(transport.CancelRequestCallCount()).To(Equal(1))
		// 		Expect(transport.CancelRequestArgsForCall(0)).To(Equal(req))
		// 	})
		//
		// 	Context("when the first request to the route service fails", func() {
		// 		BeforeEach(func() {
		// 			firstCall := true
		//
		// 			transport.RoundTripStub = func(req *http.Request) (*http.Response, error) {
		// 				var err error
		//
		// 				err = nil
		// 				if firstCall {
		// 					err = dialError
		// 				}
		// 				firstCall = false
		//
		// 				return nil, err
		// 			}
		// 		})
		//
		// 		It("does not set X-CF-Forwarded-Url to the route service URL", func() {
		// 			_, err := proxyRoundTripper.RoundTrip(req)
		// 			Expect(err).NotTo(HaveOccurred())
		// 			Expect(req.Header.Get(routeservice.RouteServiceForwardedURL)).To(Equal("http://myapp.com/"))
		// 		})
		//
		// 	})
		//
		// 	Context("when the route service is not available", func() {
		// 		var roundTripCallCount int
		//
		// 		BeforeEach(func() {
		// 			transport.RoundTripStub = func(req *http.Request) (*http.Response, error) {
		// 				roundTripCallCount++
		// 				return nil, dialError
		// 			}
		// 		})
		//
		// 		It("retries 3 times", func() {
		// 			_, err := proxyRoundTripper.RoundTrip(req)
		// 			Expect(err).To(HaveOccurred())
		// 			Expect(roundTripCallCount).To(Equal(3))
		// 		})
		// 	})
		// })
	})
})
