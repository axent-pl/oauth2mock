package di

import (
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"sync"
)

// dependencyInjectionRegistry holds registered providers and consumers
// and ensures thread-safe access with separate mutexes.
type dependencyInjectionRegistry struct {
	providersMU sync.RWMutex  // Mutex for providers
	providers   []interface{} // List of registered providers

	consumersMU sync.RWMutex  // Mutex for consumers
	consumers   []interface{} // List of registered consumers
}

// singleton instance of the DI registry.
var di dependencyInjectionRegistry = dependencyInjectionRegistry{}

// Register registers an object as both a provider and a consumer.
// Thread-safe.
func Register(s interface{}) {
	di.providersMU.Lock()
	di.providers = append(di.providers, s)
	di.providersMU.Unlock()
	slog.Debug("registered as dependency injection provider", "type", fmt.Sprintf("%T", s))

	di.consumersMU.Lock()
	di.consumers = append(di.consumers, s)
	di.consumersMU.Unlock()
	slog.Debug("registered as dependency injection consumer", "type", fmt.Sprintf("%T", s))
}

// RegisterProvider registers an object as a provider only.
// Thread-safe.
func RegisterProvider(p interface{}) {
	di.providersMU.Lock()
	di.providers = append(di.providers, p)
	di.providersMU.Unlock()
	slog.Debug("registered as dependency injection provider", "type", fmt.Sprintf("%T", p))
}

// RegisterConsumer registers an object as a consumer only.
// Thread-safe.
func RegisterConsumer(c interface{}) {
	di.consumersMU.Lock()
	di.consumers = append(di.consumers, c)
	di.consumersMU.Unlock()
	slog.Debug("registered as dependency injection consumer", "type", fmt.Sprintf("%T", c))
}

// Wire injects dependencies into all registered consumers by calling their
// InjectXXX(*ProviderType) methods for matching provider types.
// Returns an error if a consumer is invalid.
func Wire() error {
	slog.Info("dependency wiring started")
	for _, consumer := range di.consumers {
		slog.Debug("Wiring consumer", "type", fmt.Sprintf("%T", consumer))
		if err := injectInto(consumer, di.providers); err != nil {
			slog.Error("failed to wire consumer", "type", fmt.Sprintf("%T", consumer), "error", err)
			return err
		}
	}
	slog.Info("dependency wiring done")
	return nil
}

// GiveMeInterface takes a nil interface variable of the desired type (e.g. (*MyInterface)(nil))
// and returns the first provider implementing it, already type-asserted to that interface.
// You must declare the variable of the correct type and pass it in, even if nil.
func GiveMeInterface[T any](iface T) (T, bool) {
	var zero T

	ifaceType := reflect.TypeOf((*T)(nil)).Elem()

	di.providersMU.RLock()
	defer di.providersMU.RUnlock()

	for _, p := range di.providers {
		pType := reflect.TypeOf(p)
		if pType.Implements(ifaceType) {
			slog.Debug("GiveMeInterface found provider", "interface", ifaceType.String(), "provider", fmt.Sprintf("%T", p))
			return p.(T), true
		}
	}
	slog.Warn("GiveMeInterface: no provider found for interface", "interface", ifaceType.String())
	return zero, false
}

// injectInto injects dependencies from deps into the target consumer.
// It looks for methods named "InjectXXX" that take exactly one argument,
// and calls them with the first matching provider whose type is assignable.
func injectInto(target interface{}, deps []interface{}) error {
	v := reflect.ValueOf(target)
	if v.Kind() != reflect.Ptr {
		return fmt.Errorf("inject target must be a pointer, got %T", target)
	}
	t := reflect.TypeOf(target)

	// Iterate over all methods of the target
	for i := 0; i < t.NumMethod(); i++ {
		m := t.Method(i)

		// Only consider methods starting with "Inject" and taking exactly 1 parameter
		if !strings.HasPrefix(m.Name, "Inject") || m.Type.NumIn() != 2 {
			continue
		}

		paramType := m.Type.In(1)
		for _, dep := range deps {
			if reflect.TypeOf(dep).AssignableTo(paramType) {
				slog.Debug("injecting dependency",
					"consumer", fmt.Sprintf("%T", target),
					"method", m.Name,
					"dependency", fmt.Sprintf("%T", dep),
				)

				v.MethodByName(m.Name).Call([]reflect.Value{reflect.ValueOf(dep)})
			}
		}
	}
	return nil
}
