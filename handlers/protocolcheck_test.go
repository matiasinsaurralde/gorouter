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

	"fmt"

	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/ghttp"
	"github.com/urfave/negroni"
)

var _ = FDescribe("Protocolcheck", func() {
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
			fmt.Println("inside ALR handler")
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
		time.Sleep(2 * time.Second)
	})

	AfterEach(func() {
		Expect(nextCalled).To(BeFalse())
		server.Close()
	})

	Context("http 1.1", func() {
		It("passes the request through", func() {
			conn, err := net.Dial("tcp", server.Addr())
			defer conn.Close()
			Expect(err).ToNot(HaveOccurred())
			respReader := bufio.NewReader(conn)

			conn.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
			resp, err := http.ReadResponse(respReader, nil)
			Expect(err).ToNot(HaveOccurred())

			Expect(resp.StatusCode).To(Equal(200))
		})
	})

	Context("unsupported versions of http", func() {
		FIt("returns a 400 bad request", func() {
			conn, err := net.Dial("tcp", server.Addr())
			Expect(err).ToNot(HaveOccurred())
			respReader := bufio.NewReader(conn)

			conn.Write([]byte("PUT / HTTP/1.5\r\n\r\n"))
			resp, err := http.ReadResponse(respReader, nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(alr.StatusCode).To(Equal(400))
			Expect(resp.StatusCode).To(Equal(400))
		})
	})

	Context("http2", func() {
		It("returns a 400 bad request", func() {
			conn, err := net.Dial("tcp", server.Addr())
			Expect(err).ToNot(HaveOccurred())
			respReader := bufio.NewReader(conn)

			//conn.Write([]byte("GET / HTTP/2.0\r\n\r\n"))
			conn.Write([]byte("PRI * HTTP/2.0\r\n\r\n"))

			resp, err := http.ReadResponse(respReader, nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(http.StatusBadRequest))
		})
	})
})
