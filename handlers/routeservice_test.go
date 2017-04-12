package handlers_test

import (
	"bufio"
	"bytes"
	"context"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"time"

	"code.cloudfoundry.org/gorouter/access_log/schema"
	"code.cloudfoundry.org/gorouter/common/secure"
	"code.cloudfoundry.org/gorouter/handlers"
	"code.cloudfoundry.org/gorouter/route"
	"code.cloudfoundry.org/gorouter/routeservice"
	"code.cloudfoundry.org/gorouter/routeservice/header"
	"code.cloudfoundry.org/gorouter/test_util"
	"code.cloudfoundry.org/routing-api/models"

	logger_fakes "code.cloudfoundry.org/gorouter/logger/fakes"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/urfave/negroni"
)

var _ = Describe("Route Service Handler", func() {
	var (
		handler negroni.Handler

		resp *httptest.ResponseRecorder
		req  *http.Request

		config       *routeservice.RouteServiceConfig
		crypto       *secure.AesGCM
		routePool    *route.Pool
		forwardedUrl string

		fakeLogger *logger_fakes.FakeLogger

		reqChan chan *http.Request

		nextCalled bool
	)

	nextHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		_, err := ioutil.ReadAll(req.Body)
		Expect(err).NotTo(HaveOccurred())

		reqChan <- req
		rw.WriteHeader(http.StatusTeapot)
		rw.Write([]byte("I'm a little teapot, short and stout."))

		nextCalled = true
	})

	BeforeEach(func() {
		body := bytes.NewBufferString("What are you?")
		testReq := test_util.NewRequest("GET", "my_host.com", "/resource+9-9_9?query=123&query$2=345#page1..5", body)
		forwardedUrl = "https://my_host.com/resource+9-9_9?query=123&query$2=345#page1..5"
		reqBuf := new(bytes.Buffer)
		err := testReq.Write(reqBuf)
		Expect(err).ToNot(HaveOccurred())
		req, err = http.ReadRequest(bufio.NewReader(reqBuf))
		Expect(err).ToNot(HaveOccurred())

		resp = httptest.NewRecorder()

		reqChan = make(chan *http.Request, 1)

		alr := &schema.AccessLogRecord{
			StartedAt: time.Now(),
		}
		routePool = route.NewPool(1*time.Second, "")

		req = req.WithContext(context.WithValue(req.Context(), "AccessLogRecord", alr))

		fakeLogger = new(logger_fakes.FakeLogger)

		crypto, err = secure.NewAesGCM([]byte("ABCDEFGHIJKLMNOP"))
		Expect(err).NotTo(HaveOccurred())
		config = routeservice.NewRouteServiceConfig(
			fakeLogger, true, 60*time.Second, crypto, nil, true,
		)

		nextCalled = false
	})

	AfterEach(func() {
		close(reqChan)
	})

	JustBeforeEach(func() {
		handler = handlers.NewRouteService(config, fakeLogger)
		req = req.WithContext(context.WithValue(req.Context(), "RoutePool", routePool))
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
				handler.ServeHTTP(resp, req, nextHandler)

				var passedReq *http.Request
				Eventually(reqChan).Should(Receive(&passedReq))

				Expect(passedReq.Header.Get(routeservice.RouteServiceSignature)).To(BeEmpty())
				Expect(passedReq.Header.Get(routeservice.RouteServiceMetadata)).To(BeEmpty())
				Expect(passedReq.Header.Get(routeservice.RouteServiceForwardedURL)).To(BeEmpty())
				Expect(passedReq.Context().Value(handlers.RouteServiceURLCtxKey)).To(BeNil())
				Expect(nextCalled).To(BeTrue(), "Expected the next handler to be called.")
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
				handler.ServeHTTP(resp, req, nextHandler)

				Expect(fakeLogger.InfoCallCount()).ToNot(Equal(0))
				message, _ := fakeLogger.InfoArgsForCall(0)
				Expect(message).To(Equal(`route-service-unsupported`))
				Expect(resp.Code).To(Equal(http.StatusBadGateway))
				Expect(resp.Header().Get("X-Cf-RouterError")).To(Equal(`route_service_unsupported`))
				Expect(resp.Body.String()).To(ContainSubstring(`Support for route services is disabled.`))
				Expect(nextCalled).To(BeFalse())
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
				handler.ServeHTTP(resp, req, nextHandler)

				var passedReq *http.Request
				Eventually(reqChan).Should(Receive(&passedReq))

				Expect(passedReq.Header.Get(routeservice.RouteServiceSignature)).To(BeEmpty())
				Expect(passedReq.Header.Get(routeservice.RouteServiceMetadata)).To(BeEmpty())
				Expect(passedReq.Header.Get(routeservice.RouteServiceForwardedURL)).To(BeEmpty())
				Expect(passedReq.Context().Value(handlers.RouteServiceURLCtxKey)).To(BeNil())
				Expect(nextCalled).To(BeTrue(), "Expected the next handler to be called.")
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

			It("sends the request to the route service with X-CF-Forwarded-Url using https scheme", func() {
				handler.ServeHTTP(resp, req, nextHandler)

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
				Expect(nextCalled).To(BeTrue(), "Expected the next handler to be called.")
			})

			Context("when recommendHttps is set to false", func() {
				BeforeEach(func() {
					config = routeservice.NewRouteServiceConfig(
						fakeLogger, true, 60*time.Second, crypto, nil, false,
					)
				})
				It("sends the request to the route service with X-CF-Forwarded-Url using http scheme", func() {
					handler.ServeHTTP(resp, req, nextHandler)

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
					Expect(nextCalled).To(BeTrue(), "Expected the next handler to be called.")
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
					handler.ServeHTTP(resp, req, nextHandler)

					Expect(resp.Code).To(Equal(http.StatusTeapot))

					var passedReq *http.Request
					Eventually(reqChan).Should(Receive(&passedReq))

					Expect(passedReq.Header.Get(routeservice.RouteServiceSignature)).To(BeEmpty())
					Expect(passedReq.Header.Get(routeservice.RouteServiceMetadata)).To(BeEmpty())
					Expect(passedReq.Header.Get(routeservice.RouteServiceForwardedURL)).To(BeEmpty())
					Expect(passedReq.Context().Value(handlers.RouteServiceURLCtxKey)).To(BeNil())
					Expect(nextCalled).To(BeTrue(), "Expected the next handler to be called.")
				})
			})

			Context("when a request has a route service signature but no metadata header", func() {
				BeforeEach(func() {
					reqArgs, err := config.Request("", forwardedUrl)
					Expect(err).ToNot(HaveOccurred())
					req.Header.Set(routeservice.RouteServiceSignature, reqArgs.Signature)
				})

				It("returns a 400 bad request response", func() {
					handler.ServeHTTP(resp, req, nextHandler)

					Expect(resp.Code).To(Equal(http.StatusBadRequest))
					Expect(resp.Body.String()).To(ContainSubstring("Failed to validate Route Service Signature"))
					Expect(fakeLogger.ErrorCallCount()).To(Equal(2))
					errMsg, _ := fakeLogger.ErrorArgsForCall(1)
					Expect(errMsg).To(Equal("signature-validation-failed"))

					Expect(nextCalled).To(BeFalse())
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
					handler.ServeHTTP(resp, req, nextHandler)

					Expect(resp.Code).To(Equal(http.StatusBadRequest))
					Expect(resp.Body.String()).To(ContainSubstring("Failed to validate Route Service Signature"))
					Expect(fakeLogger.ErrorCallCount()).To(Equal(2))
					errMsg, _ := fakeLogger.ErrorArgsForCall(1)
					Expect(errMsg).To(Equal("signature-validation-failed"))

					Expect(nextCalled).To(BeFalse())
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
					handler.ServeHTTP(resp, req, nextHandler)

					Expect(resp.Code).To(Equal(http.StatusBadRequest))
					Expect(resp.Body.String()).To(ContainSubstring("Failed to validate Route Service Signature"))
					Expect(fakeLogger.ErrorCallCount()).To(Equal(2))
					errMsg, _ := fakeLogger.ErrorArgsForCall(1)
					Expect(errMsg).To(Equal("signature-validation-failed"))

					Expect(nextCalled).To(BeFalse())
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
					handler.ServeHTTP(resp, req, nextHandler)

					Expect(resp.Code).To(Equal(http.StatusBadRequest))
					Expect(resp.Body.String()).To(ContainSubstring("Failed to validate Route Service Signature"))
					Expect(fakeLogger.ErrorCallCount()).To(Equal(2))
					errMsg, _ := fakeLogger.ErrorArgsForCall(1)
					Expect(errMsg).To(Equal("signature-validation-failed"))

					Expect(nextCalled).To(BeFalse())
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
						handler.ServeHTTP(resp, req, nextHandler)

						var passedReq *http.Request
						Eventually(reqChan).Should(Receive(&passedReq))

						Expect(passedReq.Header.Get(routeservice.RouteServiceSignature)).To(BeEmpty())
						Expect(passedReq.Header.Get(routeservice.RouteServiceMetadata)).To(BeEmpty())
						Expect(passedReq.Header.Get(routeservice.RouteServiceForwardedURL)).To(BeEmpty())
						Expect(passedReq.Context().Value(handlers.RouteServiceURLCtxKey)).To(BeNil())
						Expect(nextCalled).To(BeTrue(), "Expected the next handler to be called.")
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
						handler.ServeHTTP(resp, req, nextHandler)

						Expect(resp.Code).To(Equal(http.StatusBadRequest))
						Expect(resp.Body.String()).To(ContainSubstring("Failed to validate Route Service Signature"))
						Expect(fakeLogger.ErrorCallCount()).To(Equal(2))

						errMsg, _ := fakeLogger.ErrorArgsForCall(1)
						Expect(errMsg).To(Equal("signature-validation-failed"))

						Expect(nextCalled).To(BeFalse())
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
						handler.ServeHTTP(resp, req, nextHandler)

						Expect(resp.Code).To(Equal(http.StatusBadRequest))
						Expect(resp.Body.String()).To(ContainSubstring("Failed to validate Route Service Signature"))

						Expect(nextCalled).To(BeFalse())
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
				handler.ServeHTTP(resp, req, nextHandler)

				Expect(resp.Code).To(Equal(http.StatusInternalServerError))
				Expect(resp.Body.String()).To(ContainSubstring("Route service request failed."))

				Expect(nextCalled).To(BeFalse())
			})
		})

		Context("when the route service is a CF app", func() {
			var (
				routeServiceServer *httptest.Server
				applicationServer  *httptest.Server
				routeServiceCalled chan struct{}
				applicationCalled  chan struct{}
			)
			var routeService = func(rw http.ResponseWriter, req *http.Request) {
				routeServiceCalled <- struct{}{}
			}
			var application = func(rw http.ResponseWriter, req *http.Request) {
				applicationCalled <- struct{}{}
			}
			BeforeEach(func() {
				// have a route service come up on som eURL : localhost:9090
				// have an app come up with some URL : localhost: 9091
				// create an endpoint (apphost: appURL , rsURL: route service URL)
				// create an endpoint  with rs as app (apphost: rsURL , rsURL: "")
				// put the endpoint to pool

				//NewEndpoint(appId, host string, port uint16, privateInstanceId string, privateInstanceIndex string,
				//tags map[string]string, staleThresholdInSeconds int, routeServiceUrl string, modificationTag models.ModificationTag)
				routeServiceCalled = make(chan struct{}, 1)
				applicationCalled = make(chan struct{}, 1)

				routeServiceServer = httptest.NewServer(http.HandlerFunc(routeService))
				rsHost, rsPort := hostPort(routeServiceServer.URL)
				serviceEndpoint := route.NewEndpoint("", rsHost, rsPort, "", "",
					map[string]string{}, 5, "", models.ModificationTag{})

				added := routePool.Put(serviceEndpoint)
				Expect(added).To(BeTrue())

				applicationServer = httptest.NewServer(http.HandlerFunc(application))
				appHost, appPort := hostPort(applicationServer.URL)
				// remember to kill in after each
				applicatonEndpoint := route.NewEndpoint("", appHost, appPort, "", "",
					map[string]string{}, 5, routeServiceServer.URL, models.ModificationTag{})
				added = routePool.Put(applicatonEndpoint)
				Expect(added).To(BeTrue())
				req = req.WithContext(context.WithValue(req.Context(), handlers.ProxyResponseWriterCtxKey, routeServiceServer.URL))
			})
			AfterEach(func() {
				routeServiceServer.Close()
				applicationServer.Close()
			})

			FIt("should do something", func() {

			})
		})
	})
})

func hostPort(url string) (host string, portInt uint16) {
	urlParts := strings.Split(url, "http://")
	Expect(urlParts).To(HaveLen(2))
	host, port, err := net.SplitHostPort(urlParts[1])
	Expect(err).ToNot(HaveOccurred())
	var portInt64 uint64
	portInt64, err = strconv.ParseUint(port, 10, 16)
	Expect(err).ToNot(HaveOccurred())
	portInt = uint16(portInt64)
	return
}
