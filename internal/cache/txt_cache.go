package cache

import (
	"context"
	"sync"

	"danglr/internal/dnsresolver"

	"golang.org/x/sync/singleflight"
)

type TXTCache struct {
	resolver dnsresolver.Resolver
	cache    sync.Map
	group    singleflight.Group
}

func NewTXTCache(resolver dnsresolver.Resolver) *TXTCache {
	return &TXTCache{resolver: resolver}
}

func (c *TXTCache) Lookup(ctx context.Context, name string) (dnsresolver.TXTLookupResult, error) {
	if cached, ok := c.cache.Load(name); ok {
		return cached.(dnsresolver.TXTLookupResult), nil
	}

	value, err, _ := c.group.Do(name, func() (any, error) {
		if cached, ok := c.cache.Load(name); ok {
			return cached.(dnsresolver.TXTLookupResult), nil
		}
		result, err := c.resolver.LookupTXT(ctx, name)
		if err != nil {
			return nil, err
		}
		c.cache.Store(name, result)
		return result, nil
	})
	if err != nil {
		return dnsresolver.TXTLookupResult{}, err
	}
	return value.(dnsresolver.TXTLookupResult), nil
}

type NSCache struct {
	resolver dnsresolver.Resolver
	cache    sync.Map
	group    singleflight.Group
}

func NewNSCache(resolver dnsresolver.Resolver) *NSCache {
	return &NSCache{resolver: resolver}
}

func (c *NSCache) Lookup(ctx context.Context, name string) (dnsresolver.NSLookupResult, error) {
	if cached, ok := c.cache.Load(name); ok {
		return cached.(dnsresolver.NSLookupResult), nil
	}

	value, err, _ := c.group.Do(name, func() (any, error) {
		if cached, ok := c.cache.Load(name); ok {
			return cached.(dnsresolver.NSLookupResult), nil
		}
		result, err := c.resolver.LookupNS(ctx, name)
		if err != nil {
			return nil, err
		}
		c.cache.Store(name, result)
		return result, nil
	})
	if err != nil {
		return dnsresolver.NSLookupResult{}, err
	}
	return value.(dnsresolver.NSLookupResult), nil
}
