package handler

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/uber-go/zap"

	"code.cloudfoundry.org/gorouter/access_log/schema"
	router_http "code.cloudfoundry.org/gorouter/common/http"
	"code.cloudfoundry.org/gorouter/logger"
	"code.cloudfoundry.org/gorouter/metrics"
	"code.cloudfoundry.org/gorouter/proxy/utils"
	"code.cloudfoundry.org/gorouter/route"
)

const (
	MaxRetries = 3
)

var NoEndpointsAvailable = errors.New("No endpoints available")

type RequestHandler struct {
	logger    logger.Logger
	reporter  metrics.CombinedReporter
	logrecord *schema.AccessLogRecord

	request  *http.Request
	response utils.ProxyResponseWriter
}

func NewRequestHandler(request *http.Request, response utils.ProxyResponseWriter, r metrics.CombinedReporter, alr *schema.AccessLogRecord, logger logger.Logger) *RequestHandler {
	requestLogger := setupLogger(request, logger)
	return &RequestHandler{
		logger:    requestLogger,
		reporter:  r,
		logrecord: alr,
		request:   request,
		response:  response,
	}
}

func setupLogger(request *http.Request, logger logger.Logger) logger.Logger {
	tmpLogger := logger.Session("request-handler")
	return tmpLogger.With(
		zap.String("RemoteAddr", request.RemoteAddr),
		zap.String("Host", request.Host),
		zap.String("Path", request.URL.Path),
		zap.Object("X-Forwarded-For", request.Header["X-Forwarded-For"]),
		zap.Object("X-Forwarded-Proto", request.Header["X-Forwarded-Proto"]),
	)
}

func (h *RequestHandler) Logger() logger.Logger {
	return h.logger
}

func (h *RequestHandler) HandleHeartbeat(ok bool) {
	h.response.Header().Set("Cache-Control", "private, max-age=0")
	h.response.Header().Set("Expires", "0")
	if ok {
		h.logrecord.StatusCode = http.StatusOK
		h.response.WriteHeader(http.StatusOK)
		h.response.Write([]byte("ok\n"))
	} else {
		h.logrecord.StatusCode = http.StatusServiceUnavailable
		h.response.WriteHeader(http.StatusServiceUnavailable)
	}
	h.request.Close = true
}

func (h *RequestHandler) HandleUnsupportedProtocol() {
	// must be hijacked, otherwise no response is sent back
	conn, buf, err := h.hijack()
	if err != nil {
		h.writeStatus(http.StatusBadRequest, "Unsupported protocol")
		return
	}

	h.logrecord.StatusCode = http.StatusBadRequest
	fmt.Fprintf(buf, "HTTP/1.0 400 Bad Request\r\n\r\n")
	buf.Flush()
	conn.Close()
}

func (h *RequestHandler) HandleMissingRoute() {
	h.reporter.CaptureBadRequest()
	h.logger.Info("unknown-route")

	h.response.Header().Set("X-Cf-RouterError", "unknown_route")
	message := fmt.Sprintf("Requested route ('%s') does not exist.", h.request.Host)
	h.writeStatus(http.StatusNotFound, message)
}

func (h *RequestHandler) HandleBadGateway(err error, request *http.Request) {
	h.reporter.CaptureBadGateway()

	h.response.Header().Set("X-Cf-RouterError", "endpoint_failure")
	h.writeStatus(http.StatusBadGateway, "Registered endpoint failed to handle the request.")
	h.response.Done()
}

func (h *RequestHandler) HandleBadSignature(err error) {
	h.logger.Error("signature-validation-failed", zap.Error(err))

	h.writeStatus(http.StatusBadRequest, "Failed to validate Route Service Signature")
	h.response.Done()
}

func (h *RequestHandler) HandleRouteServiceFailure(err error) {
	h.logger.Error("route-service-failed", zap.Error(err))

	h.writeStatus(http.StatusInternalServerError, "Route service request failed.")
	h.response.Done()
}

func (h *RequestHandler) HandleUnsupportedRouteService() {
	h.logger.Info("route-service-unsupported")

	h.response.Header().Set("X-Cf-RouterError", "route_service_unsupported")
	h.writeStatus(http.StatusBadGateway, "Support for route services is disabled.")
	h.response.Done()
}

func (h *RequestHandler) HandleTcpRequest(iter route.EndpointIterator) {
	h.logger.Info("handling-tcp-request", zap.String("Upgrade", "tcp"))

	h.logrecord.StatusCode = http.StatusSwitchingProtocols

	err := h.serveTcp(iter)
	if err != nil {
		h.logger.Error("tcp-request-failed", zap.Error(err))
		h.writeStatus(http.StatusBadRequest, "TCP forwarding to endpoint failed.")
	}
}

func (h *RequestHandler) HandleWebSocketRequest(iter route.EndpointIterator) {
	h.logger.Info("handling-websocket-request", zap.String("Upgrade", "websocket"))

	h.logrecord.StatusCode = http.StatusSwitchingProtocols

	err := h.serveWebSocket(iter)
	if err != nil {
		h.logger.Error("websocket-request-failed", zap.Error(err))
		h.writeStatus(http.StatusBadRequest, "WebSocket request to endpoint failed.")
		h.reporter.CaptureWebSocketFailure()
		return
	}
	h.reporter.CaptureWebSocketUpdate()
}

func (h *RequestHandler) writeStatus(code int, message string) {
	body := fmt.Sprintf("%d %s: %s", code, http.StatusText(code), message)

	h.logger.Info("status", zap.String("body", body))
	h.logrecord.StatusCode = code

	http.Error(h.response, body, code)
	if code > 299 {
		h.response.Header().Del("Connection")
	}
}

func (h *RequestHandler) serveTcp(iter route.EndpointIterator) error {
	var err error
	var connection net.Conn

	client, _, err := h.hijack()
	if err != nil {
		return err
	}

	defer func() {
		client.Close()
		if connection != nil {
			connection.Close()
		}
	}()

	retry := 0
	for {
		endpoint := iter.Next()
		if endpoint == nil {
			err = NoEndpointsAvailable
			h.HandleBadGateway(err, h.request)
			return err
		}

		connection, err = net.DialTimeout("tcp", endpoint.CanonicalAddr(), 5*time.Second)
		if err == nil {
			break
		}

		iter.EndpointFailed()
		h.logger.Error("tcp-connection-failed", zap.Error(err))

		retry++
		if retry == MaxRetries {
			return err
		}
	}

	if connection != nil {
		forwardIO(client, connection)
	}

	return nil
}

func (h *RequestHandler) serveWebSocket(iter route.EndpointIterator) error {
	var err error
	var connection net.Conn

	client, _, err := h.hijack()
	if err != nil {
		return err
	}

	defer func() {
		client.Close()
		if connection != nil {
			connection.Close()
		}
	}()

	retry := 0
	for {
		endpoint := iter.Next()
		if endpoint == nil {
			err = NoEndpointsAvailable
			h.HandleBadGateway(err, h.request)
			return err
		}

		connection, err = net.DialTimeout("tcp", endpoint.CanonicalAddr(), 5*time.Second)
		if err == nil {
			h.setupRequest(endpoint)
			break
		}

		iter.EndpointFailed()
		h.logger.Error("websocket-connection-failed", zap.Error(err))

		retry++
		if retry == MaxRetries {
			return err
		}
	}

	if connection != nil {
		err = h.request.Write(connection)
		if err != nil {
			return err
		}

		forwardIO(client, connection)
	}
	return nil
}

func (h *RequestHandler) setupRequest(endpoint *route.Endpoint) {
	h.setRequestURL(endpoint.CanonicalAddr())
	h.setRequestXForwardedFor()
	SetRequestXRequestStart(h.request)
}

func (h *RequestHandler) setRequestURL(addr string) {
	h.request.URL.Scheme = "http"
	h.request.URL.Host = addr
}

func (h *RequestHandler) setRequestXForwardedFor() {
	if clientIP, _, err := net.SplitHostPort(h.request.RemoteAddr); err == nil {
		// If we aren't the first proxy retain prior
		// X-Forwarded-For information as a comma+space
		// separated list and fold multiple headers into one.
		if prior, ok := h.request.Header["X-Forwarded-For"]; ok {
			clientIP = strings.Join(prior, ", ") + ", " + clientIP
		}
		h.request.Header.Set("X-Forwarded-For", clientIP)
	}
}

func SetRequestXRequestStart(request *http.Request) {
	if _, ok := request.Header[http.CanonicalHeaderKey("X-Request-Start")]; !ok {
		request.Header.Set("X-Request-Start", strconv.FormatInt(time.Now().UnixNano()/1e6, 10))
	}
}

func SetRequestXCfInstanceId(request *http.Request, endpoint *route.Endpoint) {
	value := endpoint.PrivateInstanceId
	if value == "" {
		value = endpoint.CanonicalAddr()
	}

	request.Header.Set(router_http.CfInstanceIdHeader, value)
}

func (h *RequestHandler) hijack() (client net.Conn, io *bufio.ReadWriter, err error) {
	return h.response.Hijack()
}

func forwardIO(a, b net.Conn) {
	done := make(chan bool, 2)

	copy := func(dst io.Writer, src io.Reader) {
		// don't care about errors here
		io.Copy(dst, src)
		done <- true
	}

	go copy(a, b)
	go copy(b, a)

	<-done
}
