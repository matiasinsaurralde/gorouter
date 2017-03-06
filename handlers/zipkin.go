package handlers

import (
	"encoding/hex"
	"net/http"

	"github.com/urfave/negroni"

	"code.cloudfoundry.org/gorouter/common/secure"
	"code.cloudfoundry.org/lager"
)

const (
	B3TraceIdHeader      = "X-B3-TraceId"
	B3SpanIdHeader       = "X-B3-SpanId"
	B3ParentSpanIdHeader = "X-B3-ParentSpanId"
)

type zipkin struct {
	zipkinEnabled bool
	logger        lager.Logger
	headersToLog  *[]string // Shared state with proxy for access logs
}

func NewZipkin(enabled bool, headersToLog *[]string, logger lager.Logger) negroni.Handler {
	return &zipkin{
		zipkinEnabled: enabled,
		headersToLog:  headersToLog,
		logger:        logger,
	}
}

func (z *zipkin) ServeHTTP(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	defer next(rw, r)
	if !z.zipkinEnabled {
		return
	}

	existingTraceId := r.Header.Get(B3TraceIdHeader)
	existingSpanId := r.Header.Get(B3SpanIdHeader)

	if existingTraceId == "" || existingSpanId == "" {
		randBytes, err := secure.RandomBytes(8)
		if err != nil {
			z.logger.Error("failed-to-create-b3-trace-id", err)
			return
		}

		id := hex.EncodeToString(randBytes)
		r.Header.Set(B3TraceIdHeader, id)
		r.Header.Set(B3SpanIdHeader, r.Header.Get(B3TraceIdHeader))
	} else {
		z.logger.Debug("b3-trace-id-span-id-header-exists",
			lager.Data{
				"B3TraceIdHeader": existingTraceId,
				"B3SpanIdHeader":  existingSpanId,
			},
		)
	}

	if !contains(*z.headersToLog, B3TraceIdHeader) {
		*z.headersToLog = append(*z.headersToLog, B3TraceIdHeader)
	}

	if !contains(*z.headersToLog, B3SpanIdHeader) {
		*z.headersToLog = append(*z.headersToLog, B3SpanIdHeader)
	}

	if !contains(*z.headersToLog, B3ParentSpanIdHeader) {
		*z.headersToLog = append(*z.headersToLog, B3ParentSpanIdHeader)
	}

}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
