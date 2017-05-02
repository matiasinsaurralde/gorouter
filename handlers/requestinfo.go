package handlers

import (
	"context"
	"errors"
	"net/http"
	"time"

	"code.cloudfoundry.org/gorouter/route"

	"github.com/urfave/negroni"
)

const requestInfoCtxKey string = "RequestInfo"

type RequestInfo struct {
	StartedAt, StoppedAt time.Time
	RoutePool            *route.Pool
	RouteEndpoint        *route.Endpoint
}

func ContextRequestInfo(req *http.Request) (*RequestInfo, error) {
	ri := req.Context().Value(requestInfoCtxKey)
	if ri == nil {
		return nil, errors.New("RequestInfo not set on context.")
	}
	reqInfo, ok := ri.(*RequestInfo)
	if !ok {
		return nil, errors.New("RequestInfo is not the correct type.")
	}
	return reqInfo, nil
}

type RequestInfoHandler struct{}

func NewRequestInfo() negroni.Handler {
	return &RequestInfoHandler{}
}

func (r *RequestInfoHandler) ServeHTTP(w http.ResponseWriter, req *http.Request, next http.HandlerFunc) {
	reqInfo := new(RequestInfo)
	req = req.WithContext(context.WithValue(req.Context(), requestInfoCtxKey, reqInfo))
	reqInfo.StartedAt = time.Now()
	next(w, req)
}
