package handlers

import (
	"net/http"

	"code.cloudfoundry.org/gorouter/logger"
	"code.cloudfoundry.org/gorouter/metrics"
	"code.cloudfoundry.org/gorouter/proxy/utils"

	"github.com/uber-go/zap"
	"github.com/urfave/negroni"
)

type reporterHandler struct {
	reporter metrics.CombinedReporter
	logger   logger.Logger
}

// NewReporter creates a new handler that handles reporting backend
// responses to metrics
func NewReporter(reporter metrics.CombinedReporter, logger logger.Logger) negroni.Handler {
	return &reporterHandler{
		reporter: reporter,
		logger:   logger,
	}
}

// ServeHTTP handles reporting the response after the request has been completed
func (rh *reporterHandler) ServeHTTP(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	next(rw, r)

	requestInfo, err := ContextRequestInfo(r)
	if err != nil {
		rh.logger.Fatal("requestInfo-context", zap.Error(err))
	}

	proxyWriter := rw.(utils.ProxyResponseWriter)
	rh.reporter.CaptureRoutingResponse(proxyWriter.Status())
	rh.reporter.CaptureRoutingResponseLatency(
		requestInfo.RouteEndpoint, proxyWriter.Status(),
		requestInfo.StartedAt, requestInfo.StoppedAt.Sub(requestInfo.StartedAt),
	)
}
