package handlers_test

import (
	"context"
	"net/http"
	"net/http/httptest"

	"code.cloudfoundry.org/gorouter/access_log/schema"
	"code.cloudfoundry.org/gorouter/handlers"
	"code.cloudfoundry.org/gorouter/metrics/fakes"
	fakeRegistery "code.cloudfoundry.org/gorouter/registry/fakes"
	"code.cloudfoundry.org/gorouter/test_util"

	"code.cloudfoundry.org/gorouter/logger"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/urfave/negroni"
)

var _ = Describe("Lookup", func() {
	var (
		handler     negroni.Handler
		nextHandler http.HandlerFunc
		alr         *schema.AccessLogRecord
		logger      logger.Logger
		reg         *fakeRegistery.FakeRegistry
		rep         *fakes.FakeCombinedReporter
		resp        *httptest.ResponseRecorder
		req         *http.Request
		nextCalled  bool
	)

	nextHandler = http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		nextCalled = true
	})
	BeforeEach(func() {
		logger = test_util.NewTestZapLogger("lookup_handler")
		rep = &fakes.FakeCombinedReporter{}
		reg = &fakeRegistery.FakeRegistry{}
		handler = handlers.NewLookup(reg, rep, logger)

		req = test_util.NewRequest("GET", "example.com", "/", nil)
		resp = httptest.NewRecorder()
		alr = &schema.AccessLogRecord{
			Request: req,
		}
		req = req.WithContext(context.WithValue(req.Context(), "AccessLogRecord", alr))
	})

	Context("when there are no endpoints", func() {
		It("sends a bad request metric", func() {
			handler.ServeHTTP(resp, req, nextHandler)
			Expect(rep.CaptureBadRequestCallCount()).To(Equal(1))
		})
		It("Sets X-Cf-RouterError to unknown_route", func() {
			handler.ServeHTTP(resp, req, nextHandler)
			Expect(resp.Header().Get("X-Cf-RouterError")).To(Equal("unknown_route"))
		})
		XIt("does stuff", func() {
			handler.ServeHTTP(resp, req, nextHandler)
			Expect(nextCalled).To(BeFalse())
			Expect(alr.StatusCode).To(Equal(http.StatusNotFound))
		})
	})

})
