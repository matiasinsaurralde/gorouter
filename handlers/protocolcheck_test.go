package handlers_test

import (
	"bufio"
	"context"
	"net"
	"net/http"

	"code.cloudfoundry.org/gorouter/access_log/schema"
	"code.cloudfoundry.org/gorouter/handlers"
	"code.cloudfoundry.org/gorouter/logger"
	"code.cloudfoundry.org/gorouter/test_util"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/ghttp"
	"github.com/urfave/negroni"
)

var _ = Describe("Protocolcheck", func() {
	var (
		logger     logger.Logger
		alr        *schema.AccessLogRecord
		nextCalled bool
		server     *ghttp.Server
		n          *negroni.Negroni
	)

	BeforeEach(func() {
		logger = test_util.NewTestZapLogger("protocolcheck")
		nextCalled = false

		n = negroni.New()
		n.UseFunc(func(rw http.ResponseWriter, req *http.Request, next http.HandlerFunc) {
			alr = &schema.AccessLogRecord{
				Request: req,
			}
			req = req.WithContext(context.WithValue(req.Context(), "AccessLogRecord", alr))
			next(rw, req)
		})
		n.Use(handlers.NewProtocolCheck(logger))
		n.UseHandlerFunc(func(http.ResponseWriter, *http.Request) {
			nextCalled = true
		})

		server = ghttp.NewUnstartedServer()
		server.AppendHandlers(n.ServeHTTP)
		server.Start()
	})

	AfterEach(func() {
		Eventually(nextCalled).Should(BeTrue())
		server.Close()
	})

	Context("unsupported versions of http", func() {
		It("returns a 400 bad request", func() {
			conn, err := net.Dial("tcp", server.Addr())
			Expect(err).ToNot(HaveOccurred())
			respReader := bufio.NewReader(conn)

			conn.Write([]byte("GET / HTTP/0.9\r\n\r\n"))
			resp, err := http.ReadResponse(respReader, nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(http.StatusBadRequest))
		})
	})

	Context("http2", func() {
		BeforeEach(func() {
			server = ghttp.NewUnstartedServer()
		})
		It("returns a 400 bad request", func() {
			conn, err := net.Dial("tcp", server.Addr())
			Expect(err).ToNot(HaveOccurred())
			respReader := bufio.NewReader(conn)

			conn.Write([]byte("GET / HTTP/2.0\r\n\r\n"))
			resp, err := http.ReadResponse(respReader, nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(http.StatusBadRequest))
		})
	})
})
