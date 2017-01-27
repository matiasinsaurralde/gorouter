package handlers

import (
	"context"
	"fmt"
	"net/http"

	"code.cloudfoundry.org/gorouter/logger"
	"code.cloudfoundry.org/gorouter/metrics/reporter"
	"github.com/uber-go/zap"
	"github.com/urfave/negroni"

	"code.cloudfoundry.org/gorouter/route"

	router_http "code.cloudfoundry.org/gorouter/common/http"
)

type LookupRegistry interface {
	Lookup(uri route.Uri) *route.Pool
	LookupWithInstance(uri route.Uri, appId string, appIndex string) *route.Pool
}

type lookupHandler struct {
	registry LookupRegistry
	reporter reporter.ProxyReporter
	logger   logger.Logger
}

// NewLookup creates a handler responsible for looking up a route.
func NewLookup(registry LookupRegistry, rep reporter.ProxyReporter, logger logger.Logger) negroni.Handler {
	return &lookupHandler{
		registry: registry,
		reporter: rep,
		logger:   logger,
	}
}

func (l *lookupHandler) ServeHTTP(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	pool := l.lookup(r)
	if pool == nil {
		l.handleMissingRoute(rw, r)
		return
	}
	r = r.WithContext(context.WithValue(r.Context(), "RoutePool", pool))
	next(rw, r)
}

func (l *lookupHandler) handleMissingRoute(rw http.ResponseWriter, r *http.Request) {
	l.reporter.CaptureBadRequest()
	l.logger.Info("unknown-route")

	rw.Header().Set("X-Cf-RouterError", "unknown_route")
	writeStatus(
		rw,
		http.StatusNotFound,
		fmt.Sprintf("Requested route ('%s') does not exist.", r.Host),
		r.Context().Value("AccessLogRecord"),
		l.logger,
	)
}

func (l *lookupHandler) lookup(r *http.Request) *route.Pool {
	requestPath := r.URL.EscapedPath()

	uri := route.Uri(hostWithoutPort(r) + requestPath)
	appInstanceHeader := r.Header.Get(router_http.CfAppInstance)

	if appInstanceHeader != "" {
		appId, appIndex, err := router_http.ValidateCfAppInstance(appInstanceHeader)

		if err != nil {
			l.logger.Error("invalid-app-instance-header", zap.Error(err))
			return nil
		} else {
			return l.registry.LookupWithInstance(uri, appId, appIndex)
		}
	}

	return l.registry.Lookup(uri)
}
