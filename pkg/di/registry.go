package di

import (
	"fmt"
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
	// Add to providers
	di.providersMU.Lock()
	di.providers = append(di.providers, s)
	di.providersMU.Unlock()

	// Add to consumers
	di.consumersMU.Lock()
	di.consumers = append(di.consumers, s)
	di.consumersMU.Unlock()
}

// RegisterProvider registers an object as a provider only.
// Thread-safe.
func RegisterProvider(p interface{}) {
	di.providersMU.Lock()
	di.providers = append(di.providers, p)
	di.providersMU.Unlock()
}

// RegisterConsumer registers an object as a consumer only.
// Thread-safe.
func RegisterConsumer(c interface{}) {
	di.consumersMU.Lock()
	di.consumers = append(di.consumers, c)
	di.consumersMU.Unlock()
}

// Wire injects dependencies into all registered consumers by calling their
// InjectXXX(*ProviderType) methods for matching provider types.
// Returns an error if a consumer is invalid.
func Wire() error {
	for _, consumer := range di.consumers {
		if err := injectInto(consumer, di.providers); err != nil {
			return err
		}
	}
	return nil
}

// injectInto injects dependencies from deps into the target consumer.
// It looks for methods named "InjectXXX" that take exactly one argument,
// and calls them with the first matching provider whose type is assignable.
func injectInto(target interface{}, deps []interface{}) error {
	v := reflect.ValueOf(target)
	if v.Kind() != reflect.Ptr {
		// Consumer must be a pointer to receive injections.
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

		// Expected parameter type for this method
		paramType := m.Type.In(1)

		// Find a matching provider
		for _, dep := range deps {
			if reflect.TypeOf(dep).AssignableTo(paramType) {
				// Call the InjectXXX method with the matching provider
				v.MethodByName(m.Name).Call([]reflect.Value{reflect.ValueOf(dep)})
			}
		}
	}
	return nil
}
