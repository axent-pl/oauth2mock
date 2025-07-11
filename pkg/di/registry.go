package di

import (
	"fmt"
	"reflect"
	"strings"
	"sync"
)

type dependencyInjectionRegistry struct {
	providersMU sync.RWMutex
	providers   []interface{}
	consumersMU sync.RWMutex
	consumers   []interface{}
}

var di dependencyInjectionRegistry = dependencyInjectionRegistry{}

func Register(s interface{}) {
	di.providersMU.Lock()
	di.providers = append(di.providers, s)
	di.providersMU.Unlock()

	di.consumersMU.Lock()
	di.consumers = append(di.consumers, s)
	di.consumersMU.Unlock()
}

func RegisterProvider(p interface{}) {
	di.providersMU.Lock()
	di.providers = append(di.providers, p)
	di.providersMU.Unlock()
}

func RegisterConsumer(c interface{}) {
	di.consumersMU.Lock()
	di.consumers = append(di.consumers, c)
	di.consumersMU.Unlock()
}

func Wire() error {
	for _, consumer := range di.consumers {
		if err := injectInto(consumer, di.providers); err != nil {
			return err
		}
	}
	return nil
}

func injectInto(target interface{}, deps []interface{}) error {
	v := reflect.ValueOf(target)
	if v.Kind() != reflect.Ptr {
		return fmt.Errorf("inject target must be a pointer, got %T", target)
	}
	t := reflect.TypeOf(target)
	for i := 0; i < t.NumMethod(); i++ {
		m := t.Method(i)
		if !strings.HasPrefix(m.Name, "Inject") || m.Type.NumIn() != 2 {
			continue
		}
		paramType := m.Type.In(1)
		for _, dep := range deps {
			if reflect.TypeOf(dep).AssignableTo(paramType) {
				v.MethodByName(m.Name).Call([]reflect.Value{reflect.ValueOf(dep)})
			}
		}
	}
	return nil
}
