package tlscheck

import (
	"fmt"
	"net/netip"
	"strings"
)

// selectIPs picks at most max addresses to test, alternating IPv4 and IPv6
// (IPv4 first) so that a capped list still covers both families. Duplicates
// are removed and IPv4-mapped IPv6 addresses are treated as IPv4.
func selectIPs(addrs []netip.Addr, max int) []netip.Addr {
	seen := make(map[netip.Addr]bool)
	var v4, v6 []netip.Addr
	for _, a := range addrs {
		a = a.Unmap()
		if !a.IsValid() || seen[a] {
			continue
		}
		seen[a] = true
		if a.Is4() {
			v4 = append(v4, a)
		} else {
			v6 = append(v6, a)
		}
	}
	var out []netip.Addr
	for i := 0; len(out) < max && (i < len(v4) || i < len(v6)); i++ {
		if i < len(v4) {
			out = append(out, v4[i])
		}
		if i < len(v6) && len(out) < max {
			out = append(out, v6[i])
		}
	}
	return out
}

// mergeIssues turns per-address issues into one issue per check for the
// host. The asset stays "host:443" whatever the addresses, so finding IDs do
// not change when a CDN rotates its IPs.
//
// The merged issue takes the text of its most severe occurrence. When more
// than one address was tested, the evidence starts with which addresses are
// affected, and the description says when only some servers are.
func mergeIssues(issues []issue, checked []netip.Addr) []issue {
	if len(checked) <= 1 {
		return issues
	}

	var order []string
	groups := make(map[string][]issue)
	for _, i := range issues {
		if _, ok := groups[i.checkID]; !ok {
			order = append(order, i.checkID)
		}
		groups[i.checkID] = append(groups[i.checkID], i)
	}

	merged := make([]issue, 0, len(order))
	for _, id := range order {
		group := groups[id]
		worst := group[0]
		for _, i := range group[1:] {
			if i.severity.Rank() > worst.severity.Rank() {
				worst = i
			}
		}

		affected := make([]string, len(group))
		details := make([]string, len(group))
		for n, i := range group {
			affected[n] = i.ip.String()
			details[n] = i.evidence
		}
		tested := make([]string, len(checked))
		for n, ip := range checked {
			tested[n] = ip.String()
		}

		m := worst
		m.ip = netip.Addr{}
		m.evidence = fmt.Sprintf("affected: %d of %d addresses tested (%s)\ntested: %s\n\n%s",
			len(group), len(checked), strings.Join(affected, ", "), strings.Join(tested, ", "),
			strings.Join(details, "\n\n"))
		if len(group) < len(checked) {
			m.description += fmt.Sprintf(" Only %d of the %d servers behind this name are affected, so some visitors see the problem and others do not.", len(group), len(checked))
		}
		merged = append(merged, m)
	}
	return merged
}
