package handlers_test

import (
	"bufio"
	"bytes"
	"context"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"time"

	"code.cloudfoundry.org/gorouter/access_log/schema"
	"code.cloudfoundry.org/gorouter/common/secure"
	"code.cloudfoundry.org/gorouter/handlers"
	"code.cloudfoundry.org/gorouter/proxy"
	"code.cloudfoundry.org/gorouter/route"
	"code.cloudfoundry.org/gorouter/routeservice"
	"code.cloudfoundry.org/gorouter/routeservice/header"
	"code.cloudfoundry.org/gorouter/test_util"
	"code.cloudfoundry.org/routing-api/models"

	logger_fakes "code.cloudfoundry.org/gorouter/logger/fakes"
	round_tripper_fakes "code.cloudfoundry.org/gorouter/proxy/round_tripper/fakes"
	"code.cloudfoundry.org/gorouter/registry/fakes"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/urfave/negroni"
)

var _ = Describe("Route Service Handler", func() {
	var (
		fakeRegistry          *fakes.FakeRegistry
		routeServiceHandler   negroni.Handler
		fakeProxyRoundTripper *round_tripper_fakes.FakeProxyRoundTripper

		resp *httptest.ResponseRecorder
		req  *http.Request

		config       *routeservice.RouteServiceConfig
		crypto       *secure.AesGCM
		routePool    *route.Pool
		forwardedUrl string

		fakeLogger *logger_fakes.FakeLogger

		reqChan chan *http.Request

		nextCalled chan struct{}
	)

	proxyHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		_, err := ioutil.ReadAll(req.Body)
		Expect(err).NotTo(HaveOccurred())

		reqChan <- req
		rw.WriteHeader(http.StatusTeapot)
		rw.Write([]byte("I'm a little teapot, short and stout."))
		nextCalled <- struct{}{}
	})

	updateRequest := func(testReq *http.Request, routePool *route.Pool) *http.Request {
		reqBuf := new(bytes.Buffer)
		err := testReq.Write(reqBuf)
		Expect(err).ToNot(HaveOccurred())
		req, err := http.ReadRequest(bufio.NewReader(reqBuf))
		Expect(err).ToNot(HaveOccurred())
		alr := &schema.AccessLogRecord{
			StartedAt: time.Now(),
		}
		req = req.WithContext(context.WithValue(req.Context(), "AccessLogRecord", alr))
		req = req.WithContext(context.WithValue(req.Context(), "RoutePool", routePool))
		return req
	}

	BeforeEach(func() {
		fakeRegistry = &fakes.FakeRegistry{}
		routePool = route.NewPool(1*time.Second, "")
		forwardedUrl = "https://my_host.com/resource+9-9_9?query=123&query$2=345#page1..5"
		body := bytes.NewBufferString("What are you?")
		testReq := test_util.NewRequest("GET", "my_host.com", "/resource+9-9_9?query=123&query$2=345#page1..5", body)
		req = updateRequest(testReq, routePool)
		resp = httptest.NewRecorder()
		reqChan = make(chan *http.Request, 1)
		nextCalled = make(chan struct{}, 1)

		var err error
		crypto, err = secure.NewAesGCM([]byte("ABCDEFGHIJKLMNOP"))
		Expect(err).NotTo(HaveOccurred())

		fakeLogger = new(logger_fakes.FakeLogger)
		config = routeservice.NewRouteServiceConfig(
			fakeLogger, true, 60*time.Second, crypto, nil, true,
		)

		fakeProxyRoundTripper = &round_tripper_fakes.FakeProxyRoundTripper{}
	})

	JustBeforeEach(func() {
		reverseProxy := &proxy.ReverseProxy{
			Transport: fakeProxyRoundTripper,
		}
		routeServiceHandler = handlers.NewRouteService(fakeRegistry, reverseProxy, config, fakeLogger)
	})

	AfterEach(func() {
		close(reqChan)
	})

	Context("with route services disabled", func() {
		BeforeEach(func() {
			config = routeservice.NewRouteServiceConfig(fakeLogger, false, 0, nil, nil, false)
		})

		Context("for normal routes", func() {
			BeforeEach(func() {
				endpoint := route.NewEndpoint("appId", "1.1.1.1", uint16(9090), "id", "1",
					map[string]string{}, 0, "", models.ModificationTag{})

				added := routePool.Put(endpoint)
				Expect(added).To(BeTrue())
			})
			It("should not add route service metadata to the request for normal routes", func() {
				routeServiceHandler.ServeHTTP(resp, req, proxyHandler)

				var passedReq *http.Request
				Eventually(reqChan).Should(Receive(&passedReq))

				Expect(passedReq.Header.Get(routeservice.RouteServiceSignature)).To(BeEmpty())
				Expect(passedReq.Header.Get(routeservice.RouteServiceMetadata)).To(BeEmpty())
				Expect(passedReq.Header.Get(routeservice.RouteServiceForwardedURL)).To(BeEmpty())
				Expect(passedReq.Context().Value(handlers.RouteServiceURLCtxKey)).To(BeNil())
				Eventually(nextCalled).Should(Receive(), "Expected the next handler to be called.")
			})
		})

		Context("with route service URL configured for the route", func() {
			BeforeEach(func() {
				endpoint := route.NewEndpoint("appId", "1.1.1.1", uint16(9090), "id", "1",
					map[string]string{}, 0, "route-service.com", models.ModificationTag{})

				added := routePool.Put(endpoint)
				Expect(added).To(BeTrue())
			})

			It("returns 502 Bad Gateway", func() {
				routeServiceHandler.ServeHTTP(resp, req, proxyHandler)

				Expect(fakeLogger.InfoCallCount()).ToNot(Equal(0))
				message, _ := fakeLogger.InfoArgsForCall(0)
				Expect(message).To(Equal(`route-service-unsupported`))
				Expect(resp.Code).To(Equal(http.StatusBadGateway))
				Expect(resp.Header().Get("X-Cf-RouterError")).To(Equal(`route_service_unsupported`))
				Expect(resp.Body.String()).To(ContainSubstring(`Support for route services is disabled.`))
				Eventually(nextCalled).ShouldNot(Receive())
			})
		})
	})

	Context("with Route Services enabled", func() {
		Context("for normal routes", func() {
			BeforeEach(func() {
				endpoint := route.NewEndpoint("appId", "1.1.1.1", uint16(9090), "id", "1",
					map[string]string{}, 0, "", models.ModificationTag{})

				added := routePool.Put(endpoint)
				Expect(added).To(BeTrue())
			})
			It("should not add route service metadata to the request for normal routes", func() {
				routeServiceHandler.ServeHTTP(resp, req, proxyHandler)

				var passedReq *http.Request
				Eventually(reqChan).Should(Receive(&passedReq))

				Expect(passedReq.Header.Get(routeservice.RouteServiceSignature)).To(BeEmpty())
				Expect(passedReq.Header.Get(routeservice.RouteServiceMetadata)).To(BeEmpty())
				Expect(passedReq.Header.Get(routeservice.RouteServiceForwardedURL)).To(BeEmpty())
				Expect(passedReq.Context().Value(handlers.RouteServiceURLCtxKey)).To(BeNil())
				Eventually(nextCalled).Should(Receive(), "Expected the next handler to be called.")
			})
		})

		Context("with route service URL configured for the route", func() {
			BeforeEach(func() {
				endpoint := route.NewEndpoint(
					"appId", "1.1.1.1", uint16(9090), "id", "1", map[string]string{}, 0,
					"https://route-service.com", models.ModificationTag{},
				)

				added := routePool.Put(endpoint)
				Expect(added).To(BeTrue())
			})

			FIt("sends the request to the route service with X-CF-Forwarded-Url using https scheme", func() {
				routeServiceHandler.ServeHTTP(resp, req, proxyHandler)

				Expect(resp.Code).To(Equal(http.StatusTeapot))

				var passedReq *http.Request
				Eventually(reqChan).Should(Receive(&passedReq))

				Expect(passedReq.Header.Get(routeservice.RouteServiceSignature)).ToNot(BeEmpty())
				Expect(passedReq.Header.Get(routeservice.RouteServiceMetadata)).ToNot(BeEmpty())
				Expect(passedReq.Header.Get(routeservice.RouteServiceForwardedURL)).To(ContainSubstring("https://"))
				rsurl := passedReq.Context().Value(handlers.RouteServiceURLCtxKey)
				Expect(rsurl).ToNot(BeNil())
				Expect(rsurl).To(BeAssignableToTypeOf(new(url.URL)))
				routeServiceURL := rsurl.(*url.URL)
				Expect(routeServiceURL.Host).To(Equal("route-service.com"))
				Expect(routeServiceURL.Scheme).To(Equal("https"))
				Consistently(nextCalled).ShouldNot(Receive())

				Expect(fakeProxyRoundTripper.RoundTripCallCount()).To(Equal(1))
			})

			Context("when route service is a CF app", func() {
				var rsRoutePool *route.Pool

				BeforeEach(func() {
					endpoint := route.NewEndpoint(
						"rsAppId", "1.1.1.1", uint16(9090), "id", "1", map[string]string{}, 0,
						"https://route-service.com", models.ModificationTag{},
					)

					rsRoutePool = route.NewPool(1*time.Second, "route-service")
					added := rsRoutePool.Put(endpoint)
					Expect(added).To(BeTrue())

					fakeRegistry.LookupReturns(rsRoutePool)
				})

				It("looks up route service url in the registry", func() {
					routeServiceHandler.ServeHTTP(resp, req, proxyHandler)

					var passedReq *http.Request
					Eventually(reqChan).Should(Receive(&passedReq))

					Expect(fakeRegistry.LookupCallCount()).To(Equal(1))
					routeURI := fakeRegistry.LookupArgsForCall(0)
					Expect(routeURI).To(Equal(route.Uri("https://route-service.com")))

					rsURL := passedReq.Context().Value(handlers.RouteServiceURLCtxKey)
					Expect(rsURL).ToNot(BeNil())

					routeServiceURL := rsURL.(*url.URL)

					Expect(routeServiceURL.Host).To(Equal("route-service.com"))
					Expect(routeServiceURL.Scheme).To(Equal("https"))

					// check that pool on the request context is not pointing toward CF route service app
					routeServicePool := passedReq.Context().Value("RoutePool")
					Expect(routeServicePool).ToNot(BeNil())
					rsPool := routeServicePool.(*route.Pool)
					Expect(rsPool).To(Equal(rsRoutePool))

					Eventually(nextCalled).Should(Receive())
				})
			})

			Context("when recommendHttps is set to false", func() {
				BeforeEach(func() {
					config = routeservice.NewRouteServiceConfig(
						fakeLogger, true, 60*time.Second, crypto, nil, false,
					)
				})
				It("sends the request to the route service with X-CF-Forwarded-Url using http scheme", func() {
					routeServiceHandler.ServeHTTP(resp, req, proxyHandler)

					Expect(resp.Code).To(Equal(http.StatusTeapot))

					var passedReq *http.Request
					Eventually(reqChan).Should(Receive(&passedReq))

					Expect(passedReq.Header.Get(routeservice.RouteServiceSignature)).ToNot(BeEmpty())
					Expect(passedReq.Header.Get(routeservice.RouteServiceMetadata)).ToNot(BeEmpty())
					Expect(passedReq.Header.Get(routeservice.RouteServiceForwardedURL)).To(ContainSubstring("http://"))
					rsurl := passedReq.Context().Value(handlers.RouteServiceURLCtxKey)
					Expect(rsurl).ToNot(BeNil())
					Expect(rsurl).To(BeAssignableToTypeOf(new(url.URL)))
					routeServiceURL := rsurl.(*url.URL)
					Expect(routeServiceURL.Host).To(Equal("route-service.com"))
					Expect(routeServiceURL.Scheme).To(Equal("https"))
					Eventually(nextCalled).Should(Receive(), "Expected the next handler to be called.")
				})
			})

			Context("when a request has a valid route service signature and metadata header", func() {
				BeforeEach(func() {
					reqArgs, err := config.Request("", forwardedUrl)
					Expect(err).ToNot(HaveOccurred())
					req.Header.Set(routeservice.RouteServiceSignature, reqArgs.Signature)
					req.Header.Set(routeservice.RouteServiceMetadata, reqArgs.Metadata)
				})

				It("strips headers and sends the request to the backend instance", func() {
					routeServiceHandler.ServeHTTP(resp, req, proxyHandler)

					Expect(resp.Code).To(Equal(http.StatusTeapot))

					var passedReq *http.Request
					Eventually(reqChan).Should(Receive(&passedReq))

					Expect(passedReq.Header.Get(routeservice.RouteServiceSignature)).To(BeEmpty())
					Expect(passedReq.Header.Get(routeservice.RouteServiceMetadata)).To(BeEmpty())
					Expect(passedReq.Header.Get(routeservice.RouteServiceForwardedURL)).To(BeEmpty())
					Expect(passedReq.Context().Value(handlers.RouteServiceURLCtxKey)).To(BeNil())
					Eventually(nextCalled).Should(Receive(), "Expected the next handler to be called.")
				})
			})

			Context("when a request has a route service signature but no metadata header", func() {
				BeforeEach(func() {
					reqArgs, err := config.Request("", forwardedUrl)
					Expect(err).ToNot(HaveOccurred())
					req.Header.Set(routeservice.RouteServiceSignature, reqArgs.Signature)
				})

				It("returns a 400 bad request response", func() {
					routeServiceHandler.ServeHTTP(resp, req, proxyHandler)

					Expect(resp.Code).To(Equal(http.StatusBadRequest))
					Expect(resp.Body.String()).To(ContainSubstring("Failed to validate Route Service Signature"))
					Expect(fakeLogger.ErrorCallCount()).To(Equal(2))
					errMsg, _ := fakeLogger.ErrorArgsForCall(1)
					Expect(errMsg).To(Equal("signature-validation-failed"))

					Eventually(nextCalled).ShouldNot(Receive())
				})
			})

			Context("when a request has an expired route service signature header", func() {
				BeforeEach(func() {
					decodedURL, err := url.QueryUnescape(forwardedUrl)
					Expect(err).ToNot(HaveOccurred())

					signature := &header.Signature{
						RequestedTime: time.Now().Add(-2 * time.Minute),
						ForwardedUrl:  decodedURL,
					}

					signatureHeader, metadataHeader, err := header.BuildSignatureAndMetadata(crypto, signature)
					Expect(err).ToNot(HaveOccurred())
					req.Header.Set(routeservice.RouteServiceSignature, signatureHeader)
					req.Header.Set(routeservice.RouteServiceMetadata, metadataHeader)
				})

				It("returns a 400 bad request response", func() {
					routeServiceHandler.ServeHTTP(resp, req, proxyHandler)

					Expect(resp.Code).To(Equal(http.StatusBadRequest))
					Expect(resp.Body.String()).To(ContainSubstring("Failed to validate Route Service Signature"))
					Expect(fakeLogger.ErrorCallCount()).To(Equal(2))
					errMsg, _ := fakeLogger.ErrorArgsForCall(1)
					Expect(errMsg).To(Equal("signature-validation-failed"))

					Eventually(nextCalled).ShouldNot(Receive())
				})
			})

			Context("when the signature's forwarded_url does not match the request", func() {
				BeforeEach(func() {
					reqArgs, err := config.Request("", "example.com")
					Expect(err).ToNot(HaveOccurred())
					req.Header.Set(routeservice.RouteServiceSignature, reqArgs.Signature)
					req.Header.Set(routeservice.RouteServiceMetadata, reqArgs.Metadata)
				})

				It("returns a 400 bad request response", func() {
					routeServiceHandler.ServeHTTP(resp, req, proxyHandler)

					Expect(resp.Code).To(Equal(http.StatusBadRequest))
					Expect(resp.Body.String()).To(ContainSubstring("Failed to validate Route Service Signature"))
					Expect(fakeLogger.ErrorCallCount()).To(Equal(2))
					errMsg, _ := fakeLogger.ErrorArgsForCall(1)
					Expect(errMsg).To(Equal("signature-validation-failed"))

					Eventually(nextCalled).ShouldNot(Receive())
				})
			})

			Context("when a request header key does not match the crypto key in the config", func() {
				BeforeEach(func() {
					decodedURL, err := url.QueryUnescape(forwardedUrl)
					Expect(err).ToNot(HaveOccurred())

					signature := &header.Signature{
						RequestedTime: time.Now(),
						ForwardedUrl:  decodedURL,
					}

					altCrypto, err := secure.NewAesGCM([]byte("QRSTUVWXYZ123456"))
					Expect(err).NotTo(HaveOccurred())

					signatureHeader, metadataHeader, err := header.BuildSignatureAndMetadata(altCrypto, signature)
					Expect(err).ToNot(HaveOccurred())
					req.Header.Set(routeservice.RouteServiceSignature, signatureHeader)
					req.Header.Set(routeservice.RouteServiceMetadata, metadataHeader)
				})

				It("returns a 400 bad request response", func() {
					routeServiceHandler.ServeHTTP(resp, req, proxyHandler)

					Expect(resp.Code).To(Equal(http.StatusBadRequest))
					Expect(resp.Body.String()).To(ContainSubstring("Failed to validate Route Service Signature"))
					Expect(fakeLogger.ErrorCallCount()).To(Equal(2))
					errMsg, _ := fakeLogger.ErrorArgsForCall(1)
					Expect(errMsg).To(Equal("signature-validation-failed"))

					Eventually(nextCalled).ShouldNot(Receive())
				})
			})

			Context("with a previous crypto key in the config", func() {
				var cryptoPrev *secure.AesGCM
				BeforeEach(func() {
					var err error
					cryptoPrev, err = secure.NewAesGCM([]byte("QRSTUVWXYZ123456"))
					Expect(err).ToNot(HaveOccurred())
					config = routeservice.NewRouteServiceConfig(
						fakeLogger, true, 60*time.Second, crypto, cryptoPrev, true,
					)
				})

				Context("when a request header key matches the previous crypto key in the config", func() {
					BeforeEach(func() {
						decodedURL, err := url.QueryUnescape(forwardedUrl)
						Expect(err).ToNot(HaveOccurred())

						signature := &header.Signature{
							RequestedTime: time.Now(),
							ForwardedUrl:  decodedURL,
						}

						signatureHeader, metadataHeader, err := header.BuildSignatureAndMetadata(cryptoPrev, signature)
						Expect(err).ToNot(HaveOccurred())
						req.Header.Set(routeservice.RouteServiceSignature, signatureHeader)
						req.Header.Set(routeservice.RouteServiceMetadata, metadataHeader)
					})

					It("sends the request to the backend instance", func() {
						routeServiceHandler.ServeHTTP(resp, req, proxyHandler)

						var passedReq *http.Request
						Eventually(reqChan).Should(Receive(&passedReq))

						Expect(passedReq.Header.Get(routeservice.RouteServiceSignature)).To(BeEmpty())
						Expect(passedReq.Header.Get(routeservice.RouteServiceMetadata)).To(BeEmpty())
						Expect(passedReq.Header.Get(routeservice.RouteServiceForwardedURL)).To(BeEmpty())
						Expect(passedReq.Context().Value(handlers.RouteServiceURLCtxKey)).To(BeNil())
						Eventually(nextCalled).Should(Receive(), "Expected the next handler to be called.")
					})
				})

				Context("when a request has an expired route service signature header", func() {
					BeforeEach(func() {
						decodedURL, err := url.QueryUnescape(forwardedUrl)
						Expect(err).ToNot(HaveOccurred())

						signature := &header.Signature{
							RequestedTime: time.Now().Add(-2 * time.Minute),
							ForwardedUrl:  decodedURL,
						}

						signatureHeader, metadataHeader, err := header.BuildSignatureAndMetadata(cryptoPrev, signature)
						Expect(err).ToNot(HaveOccurred())
						req.Header.Set(routeservice.RouteServiceSignature, signatureHeader)
						req.Header.Set(routeservice.RouteServiceMetadata, metadataHeader)
					})

					It("returns a 400 bad request response", func() {
						routeServiceHandler.ServeHTTP(resp, req, proxyHandler)

						Expect(resp.Code).To(Equal(http.StatusBadRequest))
						Expect(resp.Body.String()).To(ContainSubstring("Failed to validate Route Service Signature"))
						Expect(fakeLogger.ErrorCallCount()).To(Equal(2))

						errMsg, _ := fakeLogger.ErrorArgsForCall(1)
						Expect(errMsg).To(Equal("signature-validation-failed"))

						Eventually(nextCalled).ShouldNot(Receive())
					})
				})

				Context("when a request header key does not match the previous crypto key in the config", func() {
					BeforeEach(func() {
						decodedURL, err := url.QueryUnescape(forwardedUrl)
						Expect(err).ToNot(HaveOccurred())

						signature := &header.Signature{
							RequestedTime: time.Now(),
							ForwardedUrl:  decodedURL,
						}

						altCrypto, err := secure.NewAesGCM([]byte("123456QRSTUVWXYZ"))
						Expect(err).NotTo(HaveOccurred())

						signatureHeader, metadataHeader, err := header.BuildSignatureAndMetadata(altCrypto, signature)
						Expect(err).ToNot(HaveOccurred())
						req.Header.Set(routeservice.RouteServiceSignature, signatureHeader)
						req.Header.Set(routeservice.RouteServiceMetadata, metadataHeader)
					})

					It("returns a 400 bad request response", func() {
						routeServiceHandler.ServeHTTP(resp, req, proxyHandler)

						Expect(resp.Code).To(Equal(http.StatusBadRequest))
						Expect(resp.Body.String()).To(ContainSubstring("Failed to validate Route Service Signature"))

						Eventually(nextCalled).ShouldNot(Receive())
					})
				})
			})
		})

		Context("when a bad route service url is used", func() {
			BeforeEach(func() {
				endpoint := route.NewEndpoint(
					"appId", "1.1.1.1", uint16(9090), "id", "1", map[string]string{}, 0,
					"https://bad%20service.com", models.ModificationTag{},
				)

				added := routePool.Put(endpoint)
				Expect(added).To(BeTrue())

			})
			It("returns a 500 internal server error response", func() {
				routeServiceHandler.ServeHTTP(resp, req, proxyHandler)

				Expect(resp.Code).To(Equal(http.StatusInternalServerError))
				Expect(resp.Body.String()).To(ContainSubstring("Route service request failed."))

				Eventually(nextCalled).ShouldNot(Receive())
			})
		})

	})
})
