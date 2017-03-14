// This file was generated by counterfeiter
package fakes

import (
	"net/http"
	"sync"
	"time"

	"code.cloudfoundry.org/gorouter/metrics"
	"code.cloudfoundry.org/gorouter/route"
)

type FakeCombinedReporter struct {
	CaptureBadRequestStub        func()
	captureBadRequestMutex       sync.RWMutex
	captureBadRequestArgsForCall []struct{}
	CaptureBadGatewayStub        func()
	captureBadGatewayMutex       sync.RWMutex
	captureBadGatewayArgsForCall []struct{}
	CaptureRoutingRequestStub        func(b *route.Endpoint)
	captureRoutingRequestMutex       sync.RWMutex
	captureRoutingRequestArgsForCall []struct {
		b *route.Endpoint
	}
	CaptureRoutingResponseStub        func(statusCode int)
	captureRoutingResponseMutex       sync.RWMutex
	captureRoutingResponseArgsForCall []struct {
		statusCode int
	}
	CaptureRoutingResponseLatencyStub        func(b *route.Endpoint, statusCode int, t time.Time, d time.Duration)
	captureRoutingResponseLatencyMutex       sync.RWMutex
	captureRoutingResponseLatencyArgsForCall []struct {
		b          *route.Endpoint
		statusCode int
		t          time.Time
		d          time.Duration
	}
	CaptureRouteServiceResponseStub        func(res *http.Response)
	captureRouteServiceResponseMutex       sync.RWMutex
	captureRouteServiceResponseArgsForCall []struct {
		res *http.Response
	}
	CaptureWebSocketUpdateStub        func()
	captureWebSocketUpdateMutex       sync.RWMutex
	captureWebSocketUpdateArgsForCall []struct{}
	CaptureWebSocketFailureStub        func()
	captureWebSocketFailureMutex       sync.RWMutex
	captureWebSocketFailureArgsForCall []struct{}
}

func (fake *FakeCombinedReporter) CaptureBadRequest() {
	fake.captureBadRequestMutex.Lock()
	fake.captureBadRequestArgsForCall = append(fake.captureBadRequestArgsForCall, struct{}{})
	fake.captureBadRequestMutex.Unlock()
	if fake.CaptureBadRequestStub != nil {
		fake.CaptureBadRequestStub()
	}
}

func (fake *FakeCombinedReporter) CaptureBadRequestCallCount() int {
	fake.captureBadRequestMutex.RLock()
	defer fake.captureBadRequestMutex.RUnlock()
	return len(fake.captureBadRequestArgsForCall)
}

func (fake *FakeCombinedReporter) CaptureBadGateway() {
	fake.captureBadGatewayMutex.Lock()
	fake.captureBadGatewayArgsForCall = append(fake.captureBadGatewayArgsForCall, struct{}{})
	fake.captureBadGatewayMutex.Unlock()
	if fake.CaptureBadGatewayStub != nil {
		fake.CaptureBadGatewayStub()
	}
}

func (fake *FakeCombinedReporter) CaptureBadGatewayCallCount() int {
	fake.captureBadGatewayMutex.RLock()
	defer fake.captureBadGatewayMutex.RUnlock()
	return len(fake.captureBadGatewayArgsForCall)
}

func (fake *FakeCombinedReporter) CaptureRoutingRequest(b *route.Endpoint) {
	fake.captureRoutingRequestMutex.Lock()
	fake.captureRoutingRequestArgsForCall = append(fake.captureRoutingRequestArgsForCall, struct {
		b *route.Endpoint
	}{b})
	fake.captureRoutingRequestMutex.Unlock()
	if fake.CaptureRoutingRequestStub != nil {
		fake.CaptureRoutingRequestStub(b)
	}
}

func (fake *FakeCombinedReporter) CaptureRoutingRequestCallCount() int {
	fake.captureRoutingRequestMutex.RLock()
	defer fake.captureRoutingRequestMutex.RUnlock()
	return len(fake.captureRoutingRequestArgsForCall)
}

func (fake *FakeCombinedReporter) CaptureRoutingRequestArgsForCall(i int) *route.Endpoint {
	fake.captureRoutingRequestMutex.RLock()
	defer fake.captureRoutingRequestMutex.RUnlock()
	return fake.captureRoutingRequestArgsForCall[i].b
}

func (fake *FakeCombinedReporter) CaptureRoutingResponse(statusCode int) {
	fake.captureRoutingResponseMutex.Lock()
	fake.captureRoutingResponseArgsForCall = append(fake.captureRoutingResponseArgsForCall, struct {
		statusCode int
	}{statusCode})
	fake.captureRoutingResponseMutex.Unlock()
	if fake.CaptureRoutingResponseStub != nil {
		fake.CaptureRoutingResponseStub(statusCode)
	}
}

func (fake *FakeCombinedReporter) CaptureRoutingResponseCallCount() int {
	fake.captureRoutingResponseMutex.RLock()
	defer fake.captureRoutingResponseMutex.RUnlock()
	return len(fake.captureRoutingResponseArgsForCall)
}

func (fake *FakeCombinedReporter) CaptureRoutingResponseArgsForCall(i int) int {
	fake.captureRoutingResponseMutex.RLock()
	defer fake.captureRoutingResponseMutex.RUnlock()
	return fake.captureRoutingResponseArgsForCall[i].statusCode
}

func (fake *FakeCombinedReporter) CaptureRoutingResponseLatency(b *route.Endpoint, statusCode int, t time.Time, d time.Duration) {
	fake.captureRoutingResponseLatencyMutex.Lock()
	fake.captureRoutingResponseLatencyArgsForCall = append(fake.captureRoutingResponseLatencyArgsForCall, struct {
		b          *route.Endpoint
		statusCode int
		t          time.Time
		d          time.Duration
	}{b, statusCode, t, d})
	fake.captureRoutingResponseLatencyMutex.Unlock()
	if fake.CaptureRoutingResponseLatencyStub != nil {
		fake.CaptureRoutingResponseLatencyStub(b, statusCode, t, d)
	}
}

func (fake *FakeCombinedReporter) CaptureRoutingResponseLatencyCallCount() int {
	fake.captureRoutingResponseLatencyMutex.RLock()
	defer fake.captureRoutingResponseLatencyMutex.RUnlock()
	return len(fake.captureRoutingResponseLatencyArgsForCall)
}

func (fake *FakeCombinedReporter) CaptureRoutingResponseLatencyArgsForCall(i int) (*route.Endpoint, int, time.Time, time.Duration) {
	fake.captureRoutingResponseLatencyMutex.RLock()
	defer fake.captureRoutingResponseLatencyMutex.RUnlock()
	return fake.captureRoutingResponseLatencyArgsForCall[i].b, fake.captureRoutingResponseLatencyArgsForCall[i].statusCode, fake.captureRoutingResponseLatencyArgsForCall[i].t, fake.captureRoutingResponseLatencyArgsForCall[i].d
}

func (fake *FakeCombinedReporter) CaptureRouteServiceResponse(res *http.Response) {
	fake.captureRouteServiceResponseMutex.Lock()
	fake.captureRouteServiceResponseArgsForCall = append(fake.captureRouteServiceResponseArgsForCall, struct {
		res *http.Response
	}{res})
	fake.captureRouteServiceResponseMutex.Unlock()
	if fake.CaptureRouteServiceResponseStub != nil {
		fake.CaptureRouteServiceResponseStub(res)
	}
}

func (fake *FakeCombinedReporter) CaptureRouteServiceResponseCallCount() int {
	fake.captureRouteServiceResponseMutex.RLock()
	defer fake.captureRouteServiceResponseMutex.RUnlock()
	return len(fake.captureRouteServiceResponseArgsForCall)
}

func (fake *FakeCombinedReporter) CaptureRouteServiceResponseArgsForCall(i int) *http.Response {
	fake.captureRouteServiceResponseMutex.RLock()
	defer fake.captureRouteServiceResponseMutex.RUnlock()
	return fake.captureRouteServiceResponseArgsForCall[i].res
}

func (fake *FakeCombinedReporter) CaptureWebSocketUpdate() {
	fake.captureWebSocketUpdateMutex.Lock()
	fake.captureWebSocketUpdateArgsForCall = append(fake.captureWebSocketUpdateArgsForCall, struct{}{})
	fake.captureWebSocketUpdateMutex.Unlock()
	if fake.CaptureWebSocketUpdateStub != nil {
		fake.CaptureWebSocketUpdateStub()
	}
}

func (fake *FakeCombinedReporter) CaptureWebSocketUpdateCallCount() int {
	fake.captureWebSocketUpdateMutex.RLock()
	defer fake.captureWebSocketUpdateMutex.RUnlock()
	return len(fake.captureWebSocketUpdateArgsForCall)
}

func (fake *FakeCombinedReporter) CaptureWebSocketFailure() {
	fake.captureWebSocketFailureMutex.Lock()
	fake.captureWebSocketFailureArgsForCall = append(fake.captureWebSocketFailureArgsForCall, struct{}{})
	fake.captureWebSocketFailureMutex.Unlock()
	if fake.CaptureWebSocketFailureStub != nil {
		fake.CaptureWebSocketFailureStub()
	}
}

func (fake *FakeCombinedReporter) CaptureWebSocketFailureCallCount() int {
	fake.captureWebSocketFailureMutex.RLock()
	defer fake.captureWebSocketFailureMutex.RUnlock()
	return len(fake.captureWebSocketFailureArgsForCall)
}

var _ metrics.CombinedReporter = new(FakeCombinedReporter)
