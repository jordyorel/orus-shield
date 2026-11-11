// Package all lists every module the product ships. The worker uses it to
// build its registry, and orusctl to validate module names.
//
// Adding a module means adding a line here, never changing the engine.
package all

import (
	"github.com/jordyorel/orus-shield/engine/internal/dialer"
	"github.com/jordyorel/orus-shield/engine/internal/module"
	"github.com/jordyorel/orus-shield/engine/internal/modules/cdn"
	"github.com/jordyorel/orus-shield/engine/internal/modules/discovery"
	"github.com/jordyorel/orus-shield/engine/internal/modules/email"
	"github.com/jordyorel/orus-shield/engine/internal/modules/ports"
	"github.com/jordyorel/orus-shield/engine/internal/modules/tlscheck"
	"github.com/jordyorel/orus-shield/engine/internal/modules/web"
	"github.com/jordyorel/orus-shield/engine/internal/resolver"
)

// Registry returns a registry with every module, using dns (see
// resolver.FromEnv) and the real dialer.
func Registry(dns resolver.Resolver) (*module.Registry, error) {
	reg := module.NewRegistry()
	for _, m := range []module.Module{
		email.New(dns),
		tlscheck.New(dns, dialer.NewSystem()),
		ports.New(dns, dialer.NewSystem()),
		cdn.New(dns, dialer.NewSystem()),
		web.New(dns, dialer.NewSystem()),
		discovery.New(dns, discovery.Crtsh{}),
	} {
		if err := reg.Register(m); err != nil {
			return nil, err
		}
	}
	return reg, nil
}
