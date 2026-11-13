// Package plan defines the offers and what each one allows, and decides
// which offer an organization has right now from its subscription.
//
// It is pure: no database, no clock of its own. The API enforces the
// limits when a customer asks for something (add a domain, invite a member,
// launch a scan, set a schedule), and the worker enforces them again when a
// scan runs, because a subscription can lapse between the two.
//
// Prices are a proposal (2026-11-11) that Jordy has not validated yet: they
// are shown in the dashboard but nothing charges them until a payment
// provider is connected.
package plan

import (
	"time"
)

// ID identifies an offer. Stored in subscriptions.plan: never rename one.
type ID string

const (
	Discovery  ID = "discovery"  // « Gratuit »
	SME        ID = "sme"        // « Essentiel »
	Pro        ID = "pro"        // « Pro »
	Enterprise ID = "enterprise" // « Entreprise », on quote
)

// Frequency is how often scheduled scans may run, from least to most often.
type Frequency int

const (
	Monthly Frequency = iota + 1
	Weekly
	Daily
)

// Plan is one offer.
type Plan struct {
	ID   ID
	Name string // French name, as the dashboard shows it
	// Limits. 0 means unlimited.
	Domains      int
	HostsPerScan int // names one scan covers (module.MaxHosts at most)
	Members      int
	// ActiveModules: port scan, known vulnerabilities (verified domains).
	// Without it, only passive checks run.
	ActiveModules bool
	// MaxFrequency is the most frequent schedule allowed.
	MaxFrequency Frequency
	Alerts       bool // email alerts on new critical and high findings
	Reports      bool // PDF reports
	Threats      bool // emerging threat rescans
	// DeepScans: the deep profile (over 1 000 ports with versions, deep
	// web scan). DeepScansPerMonth bounds how many scans run with it per
	// calendar month (UTC); 0 is unlimited. Beyond it, scans run as
	// standard ones.
	DeepScans         bool
	DeepScansPerMonth int
	// APIScans: declared APIs (OpenAPI, GraphQL) are scanned.
	APIScans bool
	// AuthScans: a test account lets the deep web scan and the API scan
	// reach what is behind the login.
	AuthScans bool
	// Agents: internal networks scanned by agents installed by the
	// customer (step J).
	Agents bool
	// Prices in USD, per month, billed monthly or yearly (cards and PayPal
	// through Paddle). Zero with OnQuote: set by contract.
	USDMonthly, USDYearly int
	OnQuote               bool
}

// Plans lists the offers, cheapest first.
var Plans = []Plan{
	{ID: Discovery, Name: "Gratuit", Domains: 1, HostsPerScan: 5, Members: 1,
		MaxFrequency: Monthly},
	{ID: SME, Name: "Essentiel", Domains: 3, HostsPerScan: 25, Members: 3, ActiveModules: true,
		MaxFrequency: Weekly, Alerts: true, Reports: true, Threats: true,
		USDMonthly: 35, USDYearly: 29},
	{ID: Pro, Name: "Pro", Domains: 15, HostsPerScan: 25, Members: 10, ActiveModules: true,
		MaxFrequency: Daily, Alerts: true, Reports: true, Threats: true, DeepScans: true, DeepScansPerMonth: 4, APIScans: true, AuthScans: true,
		USDMonthly: 99, USDYearly: 79},
	{ID: Enterprise, Name: "Sur devis", HostsPerScan: 25, ActiveModules: true,
		MaxFrequency: Daily, Alerts: true, Reports: true, Threats: true, DeepScans: true, APIScans: true, AuthScans: true, Agents: true, OnQuote: true},
}

// Get returns the plan with id.
func Get(id ID) (Plan, bool) {
	for _, p := range Plans {
		if p.ID == id {
			return p, true
		}
	}
	return Plan{}, false
}

// Status is a subscription's state.
type Status string

const (
	// Trialing: the plan is free until TrialEndsAt.
	Trialing Status = "trialing"
	// Active: paid until PeriodEnd (nil: no end, a contract or a manual
	// grant).
	Active Status = "active"
	// Canceled: the customer stopped it; it runs until PeriodEnd.
	Canceled Status = "canceled"
)

// Valid reports whether s is a known status.
func (s Status) Valid() bool { return s == Trialing || s == Active || s == Canceled }

// TrialDays is the length of the trial a new organization gets.
const TrialDays = 14

// GraceDays is how long a lapsed paid plan keeps working: a failed renewal
// (expired card, Paddle's retries) must not cut the service the same day.
const GraceDays = 7

// Subscription is what is stored for an organization.
type Subscription struct {
	Plan        ID
	Status      Status
	TrialEndsAt *time.Time
	PeriodEnd   *time.Time
}

// Effective is the plan in force at now and why.
type Effective struct {
	Plan Plan
	// Lapsed: the subscription ended (trial over, period over beyond the
	// grace days): the organization is back on Gratuit.
	Lapsed bool
	// InGrace: the period is over, the grace days are running.
	InGrace bool
	// Until is when the current plan stops, nil when it does not.
	Until *time.Time
}

// Resolve returns the plan in force. No subscription, or an unknown plan,
// means Gratuit: it fails towards the free offer, never towards paid
// features.
func Resolve(sub *Subscription, now time.Time) Effective {
	free, _ := Get(Discovery)
	if sub == nil {
		return Effective{Plan: free}
	}
	p, ok := Get(sub.Plan)
	if !ok {
		return Effective{Plan: free}
	}
	switch sub.Status {
	case Trialing:
		if sub.TrialEndsAt != nil && now.Before(*sub.TrialEndsAt) {
			return Effective{Plan: p, Until: sub.TrialEndsAt}
		}
	case Active, Canceled:
		if sub.PeriodEnd == nil {
			if sub.Status == Active {
				return Effective{Plan: p}
			}
			break
		}
		if now.Before(*sub.PeriodEnd) {
			return Effective{Plan: p, Until: sub.PeriodEnd}
		}
		grace := sub.PeriodEnd.AddDate(0, 0, GraceDays)
		if sub.Status == Active && now.Before(grace) {
			return Effective{Plan: p, InGrace: true, Until: &grace}
		}
	}
	return Effective{Plan: free, Lapsed: p.ID != Discovery}
}

// Allows reports whether the plan lets a schedule run as often as f.
func (p Plan) Allows(f Frequency) bool { return f <= p.MaxFrequency }

// Within reports whether n items fit a limit (0: unlimited).
func Within(n, limit int) bool { return limit == 0 || n <= limit }
