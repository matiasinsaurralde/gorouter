package router

import (
	"encoding/json"
	"fmt"
	mbus "github.com/cloudfoundry/go_cfmessagebus"
	"github.com/cloudfoundry/gorouter/stats"
	"github.com/cloudfoundry/gorouter/util"
	steno "github.com/cloudfoundry/gosteno"
	"math/rand"
	"sync"
	"time"
)

// This is a transient struct. It doesn't maintain state.
type registryMessage struct {
	Host string            `json:"host"`
	Port uint16            `json:"port"`
	Uris Uris              `json:"uris"`
	Tags map[string]string `json:"tags"`
	App  string            `json:"app"`

	PrivateInstanceId string `json:"private_instance_id"`
}

func (m registryMessage) BackendId() (b BackendId, ok bool) {
	if m.Host != "" && m.Port != 0 {
		b = BackendId(fmt.Sprintf("%s:%d", m.Host, m.Port))
		ok = true
	}

	return
}

type Registry struct {
	sync.RWMutex

	*steno.Logger

	*stats.ActiveApps
	*stats.TopApps

	byUri       map[Uri][]*RouteEndpoint
	byBackendId map[BackendId]*RouteEndpoint

	staleTracker *util.ListMap

	pruneStaleDropletsInterval time.Duration
	dropletStaleThreshold      time.Duration

	messageBus mbus.MessageBus

	timeOfLastUpdate time.Time
}

func NewRegistry(c *Config, messageBusClient mbus.MessageBus) *Registry {
	r := &Registry{
		messageBus: messageBusClient,
	}

	r.Logger = steno.NewLogger("router.registry")

	r.ActiveApps = stats.NewActiveApps()
	r.TopApps = stats.NewTopApps()

	r.byUri = make(map[Uri][]*RouteEndpoint)
	r.byBackendId = make(map[BackendId]*RouteEndpoint)

	r.staleTracker = util.NewListMap()

	r.pruneStaleDropletsInterval = c.PruneStaleDropletsInterval
	r.dropletStaleThreshold = c.DropletStaleThreshold

	return r
}

func (registry *Registry) StartPruningCycle() {
	go registry.checkAndPrune()
}

func (registry *Registry) isStateStale() bool {
	return !registry.messageBus.Ping()
}

func (registry *Registry) NumUris() int {
	registry.RLock()
	defer registry.RUnlock()

	return len(registry.byUri)
}

func (r *Registry) NumBackends() int {
	r.RLock()
	defer r.RUnlock()

	return len(r.byBackendId)
}

func (r *Registry) registerUri(b *RouteEndpoint, u Uri) {
	u = u.ToLower()

	ok := b.register(u)
	if ok {
		x := r.byUri[u]
		r.byUri[u] = append(x, b)
	}
}

func (registry *Registry) Register(message *registryMessage) {
	i, ok := message.BackendId()
	if !ok || len(message.Uris) == 0 {
		return
	}

	registry.Lock()
	defer registry.Unlock()

	backend, ok := registry.byBackendId[i]
	if !ok {
		backend = newBackend(i, message, registry.Logger)
		registry.byBackendId[i] = backend
	}

	for _, uri := range message.Uris {
		registry.registerUri(backend, uri)
	}

	backend.updated_at = time.Now()

	registry.staleTracker.PushBack(backend)
	registry.timeOfLastUpdate = time.Now()
}

func (registry *Registry) unregisterUri(backend *RouteEndpoint, uri Uri) {
	uri = uri.ToLower()

	ok := backend.unregister(uri)
	if ok {
		backends := registry.byUri[uri]
		for i, b := range backends {
			if b == backend {
				// Remove b from list of backends
				backends[i] = backends[len(backends)-1]
				backends = backends[:len(backends)-1]
				break
			}
		}

		if len(backends) == 0 {
			delete(registry.byUri, uri)
		} else {
			registry.byUri[uri] = backends
		}
	}

	// Remove backend if it no longer has uris
	if len(backend.U) == 0 {
		delete(registry.byBackendId, backend.BackendId)
		registry.staleTracker.Delete(backend)
	}
}

func (registry *Registry) Unregister(message *registryMessage) {
	id, ok := message.BackendId()
	if !ok {
		return
	}

	registry.Lock()
	defer registry.Unlock()

	registryForId, ok := registry.byBackendId[id]
	if !ok {
		return
	}

	for _, uri := range message.Uris {
		registry.unregisterUri(registryForId, uri)
	}
}

func (registry *Registry) pruneStaleDroplets() {
	for registry.staleTracker.Len() > 0 {
		backend := registry.staleTracker.Front().(*RouteEndpoint)
		if !registry.IsStale(backend) {
			log.Infof("Droplet is not stale; NOT pruning: %v", backend.BackendId)
			break
		}

		log.Infof("Pruning stale droplet: %v ", backend.BackendId)

		for _, uri := range backend.U {
			registry.unregisterUri(backend, uri)
		}
	}
}

func (registry *Registry) IsStale(backend *RouteEndpoint) bool {
	return backend.updated_at.Add(registry.dropletStaleThreshold).Before(time.Now())
}

func (registry *Registry) pauseStaleTracker() {
	for routeElement := registry.staleTracker.FrontElement(); routeElement != nil; routeElement = routeElement.Next() {
		routeElement.Value.(*RouteEndpoint).updated_at = time.Now()
	}
}

func (registry *Registry) PruneStaleDroplets() {
	if registry.isStateStale() {
		log.Info("State is stale; NOT pruning")
		registry.pauseStaleTracker()
		return
	}

	registry.Lock()
	defer registry.Unlock()

	registry.pruneStaleDroplets()
}

func (r *Registry) checkAndPrune() {
	if r.pruneStaleDropletsInterval == 0 {
		return
	}

	tick := time.Tick(r.pruneStaleDropletsInterval)
	for {
		select {
		case <-tick:
			log.Debug("Start to check and prune stale droplets")
			r.PruneStaleDroplets()
		}
	}
}

func (r *Registry) Lookup(host string) (*RouteEndpoint, bool) {
	r.RLock()
	defer r.RUnlock()

	x, ok := r.byUri[Uri(host).ToLower()]
	if !ok {
		return nil, false
	}

	// Return random backend from slice of backends for the specified uri
	return x[rand.Intn(len(x))], true
}

func (r *Registry) LookupByPrivateInstanceId(host string, p string) (*RouteEndpoint, bool) {
	r.RLock()
	defer r.RUnlock()

	x, ok := r.byUri[Uri(host).ToLower()]
	if !ok {
		return nil, false
	}

	for _, b := range x {
		if b.PrivateInstanceId == p {
			return b, true
		}
	}

	return nil, false
}

func (r *Registry) CaptureRoutingRequest(x *RouteEndpoint, t time.Time) {
	if x.ApplicationId != "" {
		r.ActiveApps.Mark(x.ApplicationId, t)
		r.TopApps.Mark(x.ApplicationId, t)
	}
}

func (r *Registry) MarshalJSON() ([]byte, error) {
	r.RLock()
	defer r.RUnlock()

	return json.Marshal(r.byUri)
}