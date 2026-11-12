// Command orusctl is a development tool to manage targets and scans until
// the API exists (roadmap step 7).
//
// It goes through the store like the API will, so every scan it starts is
// recorded in the audit log. A target becomes verified only through the DNS
// check of package ownership; there is no way to force it (security rule 1).
//
// Every target belongs to an organization. Commands about targets work in
// one organization at a time, through the same org-scoped store handle the
// API will use (store.Org): -org NAME|ID, or ORUS_ORG, or "Default" (created
// by the migration that introduced organizations).
//
// Usage:
//
//	orusctl org add [-as NAME] <name>
//	orusctl org list
//	orusctl org plan [-org ORG] [-until YYYY-MM-DD | -trial DAYS] [-as NAME] [<offer>]
//	orusctl user add [-org ORG] [-role admin|viewer] [-as NAME] <email>
//	orusctl user member [-org ORG] [-role admin|viewer] [-as NAME] <email>
//	orusctl user reset [-as NAME] <email>
//	orusctl user reset-mfa [-as NAME] <email>
//	orusctl target add [-org ORG] [-rate N] [-exclusions JSON] <domain>
//	orusctl target show [-org ORG] <domain>
//	orusctl target verify-token [-org ORG] [-as NAME] <domain>
//	orusctl target verify [-org ORG] [-as NAME] <domain>
//	orusctl scan [-org ORG] [-as NAME] <domain> [module ...]
//	orusctl status [-org ORG] <scan-id>
//	orusctl findings [-org ORG] [-v] <domain>
//	orusctl assets [-org ORG] [-all] <domain>
//	orusctl posture [-org ORG] [-v] <domain>
//	orusctl audit [-org ORG] <domain>
//
// It reads ORUS_DATABASE_URL (and optionally ORUS_ORG) from the environment.
package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"os/signal"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/gate"
	"github.com/jordyorel/orus-shield/engine/internal/modules/all"
	"github.com/jordyorel/orus-shield/engine/internal/ownership"
	"github.com/jordyorel/orus-shield/engine/internal/plan"
	"github.com/jordyorel/orus-shield/engine/internal/resolver"
	"github.com/jordyorel/orus-shield/engine/internal/store"
)

const usage = `usage:
  orusctl org add [-as NAME] <name>
  orusctl org list
  orusctl org plan [-org ORG] [-until YYYY-MM-DD | -trial DAYS] [<offer>]
                                                               (shows the offer, or sets it: gratuit,
                                                               essentiel, pro, sur-devis; no payment yet)
  orusctl user add [-org ORG] [-role admin|viewer] <email>     (prints a one-time setup token)
  orusctl user member [-org ORG] [-role admin|viewer] <email>  (adds to another org or changes role)
  orusctl user reset <email>                                   (new setup token: password reset)
  orusctl user reset-mfa <email>                               (lost phone: removes MFA, closes sessions)
  orusctl target add [-org ORG] [-rate N] [-exclusions JSON] <domain>
  orusctl target show [-org ORG] <domain>
  orusctl target verify-token [-org ORG] [-as NAME] <domain>   (prints the DNS record to publish)
  orusctl target verify [-org ORG] [-as NAME] <domain>         (checks it)
  orusctl scan [-org ORG] [-as NAME] <domain> [module ...]   (default: every module)
  orusctl status [-org ORG] <scan-id>
  orusctl findings [-org ORG] [-v] <domain>
  orusctl assets [-org ORG] [-all] <domain>          (inventory; -all: include gone assets)
  orusctl posture [-org ORG] [-v] <domain>           (score and history; -v: every check)
  orusctl audit [-org ORG] <domain>

ORG is an organization name or ID; default: $ORUS_ORG, else "Default".
Flags go before the positional arguments. ORUS_DATABASE_URL must be set.`

// errUsage marks command line mistakes, reported with the usage text.
var errUsage = errors.New("invalid usage")

// defaultOrg is the organization created by the migration that introduced
// organizations.
const defaultOrg = "Default"

// Admin is the part of store.Store orusctl uses to manage organizations.
type Admin interface {
	CreateOrganization(ctx context.Context, name, actor string) (store.Organization, error)
	ListOrganizations(ctx context.Context) ([]store.Organization, error)
	CreateUser(ctx context.Context, email string) (store.User, error)
	UserByEmail(ctx context.Context, email string) (store.User, error)
	SetMembership(ctx context.Context, userID, orgID, role, actor string) error
	IssueSetupToken(ctx context.Context, userID string, ttl time.Duration, actor string) (string, error)
	ResetMFA(ctx context.Context, userID, actor string) error
	SubscriptionOf(ctx context.Context, orgID string) (*plan.Subscription, error)
	SetSubscription(ctx context.Context, orgID string, sub plan.Subscription, provider, actor string) error
}

// setupTokenTTL is how long a new user has to choose a password.
const setupTokenTTL = 24 * time.Hour

// OrgStore is the part of store.Org orusctl uses: everything about targets
// goes through an org-scoped handle, like the API.
type OrgStore interface {
	CreateTarget(ctx context.Context, nt store.NewTarget) (store.Target, error)
	TargetByDomain(ctx context.Context, domain string) (store.Target, error)
	EnqueueScan(ctx context.Context, targetID string, modules []string, requestedBy string) (store.Scan, error)
	GetScan(ctx context.Context, id string) (store.Scan, error)
	ListFindings(ctx context.Context, targetID string) ([]finding.Finding, error)
	FindingHistory(ctx context.Context, targetID, findingID string) ([]store.FindingEvent, error)
	ListAssets(ctx context.Context, targetID string, includeGone bool) ([]store.Asset, error)
	CheckStatuses(ctx context.Context, targetID string) ([]store.CheckState, error)
	PostureHistory(ctx context.Context, targetID string, limit int) ([]store.PostureSnapshot, error)
	AuditLog(ctx context.Context, target string) ([]store.AuditEntry, error)
}

// OrgOpener finds an organization by name or ID and returns its scoped
// store and a verifier working through that store.
type OrgOpener func(ctx context.Context, ref string) (store.Organization, OrgStore, Verifier, error)

// Verifier is the part of ownership.Verifier orusctl uses.
type Verifier interface {
	Instructions(ctx context.Context, targetID, actor string) (ownership.Instructions, error)
	Verify(ctx context.Context, targetID, actor string) error
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	err := func() error {
		if len(os.Args) < 2 {
			return errUsage
		}
		url := os.Getenv("ORUS_DATABASE_URL")
		if url == "" {
			return errors.New("ORUS_DATABASE_URL is not set")
		}
		st, err := store.Open(ctx, url)
		if err != nil {
			return err
		}
		defer st.Close()
		dns, err := resolver.FromEnv(os.Getenv) // ORUS_DNS_SERVER, like the worker
		if err != nil {
			return fmt.Errorf("ORUS_DNS_SERVER: %w", err)
		}
		reg, err := all.Registry(dns, all.Options{})
		if err != nil {
			return err
		}
		var ids []string
		for _, m := range reg.All() {
			ids = append(ids, m.Info().ID)
		}
		c := cli{
			admin: st, openOrg: storeOpener(st, dns),
			out: os.Stdout, modules: ids, defaultActor: defaultActor(os.Getenv),
			defaultOrg: cmp.Or(os.Getenv("ORUS_ORG"), defaultOrg),
		}
		return c.run(ctx, os.Args[1:])
	}()
	if errors.Is(err, errUsage) {
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "orusctl:", err)
		os.Exit(1)
	}
}

// storeOpener resolves organizations in st. The verifier gets the org-scoped
// handle too, so verifying cannot touch another organization's target.
func storeOpener(st *store.Store, dns resolver.Resolver) OrgOpener {
	return func(ctx context.Context, ref string) (store.Organization, OrgStore, Verifier, error) {
		org, err := st.FindOrganization(ctx, ref)
		if err != nil {
			return store.Organization{}, nil, nil, err
		}
		h, err := st.Org(org.ID)
		if err != nil {
			return store.Organization{}, nil, nil, err
		}
		return org, h, ownership.New(h, dns), nil
	}
}

// defaultActor names who runs the command in the audit log.
func defaultActor(getenv func(string) string) string {
	if u := getenv("USER"); u != "" {
		return "cli:" + u
	}
	return "cli:unknown"
}

type cli struct {
	admin        Admin
	openOrg      OrgOpener
	out          io.Writer
	modules      []string // known module IDs
	defaultActor string
	defaultOrg   string // used when -org is not given
}

// orgFlag adds -org to fs.
func (c cli) orgFlag(fs *flag.FlagSet) *string {
	return fs.String("org", c.defaultOrg, "organization name or ID")
}

func (c cli) run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errUsage
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "org":
		if len(rest) == 0 {
			return fmt.Errorf("%w: org needs a subcommand (add, list, plan)", errUsage)
		}
		switch rest[0] {
		case "add":
			return c.orgAdd(ctx, rest[1:])
		case "list":
			return c.orgList(ctx, rest[1:])
		case "plan":
			return c.orgPlan(ctx, rest[1:])
		}
		return fmt.Errorf("%w: unknown org subcommand %q", errUsage, rest[0])
	case "user":
		if len(rest) == 0 {
			return fmt.Errorf("%w: user needs a subcommand (add, member, reset, reset-mfa)", errUsage)
		}
		switch rest[0] {
		case "add":
			return c.userAdd(ctx, rest[1:])
		case "member":
			return c.userMember(ctx, rest[1:])
		case "reset":
			return c.userReset(ctx, rest[1:])
		case "reset-mfa":
			return c.userResetMFA(ctx, rest[1:])
		}
		return fmt.Errorf("%w: unknown user subcommand %q", errUsage, rest[0])
	case "target":
		if len(rest) == 0 {
			return fmt.Errorf("%w: target needs a subcommand (add, show, verify-token, verify)", errUsage)
		}
		switch rest[0] {
		case "add":
			return c.targetAdd(ctx, rest[1:])
		case "show":
			return c.targetShow(ctx, rest[1:])
		case "verify-token":
			return c.verifyToken(ctx, rest[1:])
		case "verify":
			return c.verify(ctx, rest[1:])
		}
		return fmt.Errorf("%w: unknown target subcommand %q", errUsage, rest[0])
	case "scan":
		return c.scan(ctx, rest)
	case "status":
		return c.status(ctx, rest)
	case "findings":
		return c.findings(ctx, rest)
	case "assets":
		return c.assets(ctx, rest)
	case "posture":
		return c.posture(ctx, rest)
	case "audit":
		return c.audit(ctx, rest)
	}
	return fmt.Errorf("%w: unknown command %q", errUsage, cmd)
}

// parse parses flags and checks the number of positional arguments.
func parse(fs *flag.FlagSet, args []string, minArgs int) ([]string, error) {
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", errUsage, fs.Name(), err)
	}
	if fs.NArg() < minArgs {
		return nil, fmt.Errorf("%w: %s: missing argument", errUsage, fs.Name())
	}
	return fs.Args(), nil
}

func (c cli) orgAdd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("org add", flag.ContinueOnError)
	actor := fs.String("as", c.defaultActor, "requester recorded in the audit log")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	org, err := c.admin.CreateOrganization(ctx, strings.TrimSpace(strings.Join(pos, " ")), *actor)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.out, "organization %q created (id %s)\n", org.Name, org.ID)
	return nil
}

func (c cli) orgList(ctx context.Context, args []string) error {
	if _, err := parse(flag.NewFlagSet("org list", flag.ContinueOnError), args, 0); err != nil {
		return err
	}
	orgs, err := c.admin.ListOrganizations(ctx)
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(c.out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tCREATED")
	for _, o := range orgs {
		fmt.Fprintf(w, "%s\t%s\t%s\n", o.ID, o.Name, o.CreatedAt.Format(time.RFC3339))
	}
	return w.Flush()
}

// userFlags parses -org, -role and -as for the user commands.
func (c cli) userFlags(name string, args []string) (orgRef, role, actor string, pos []string, err error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	o := c.orgFlag(fs)
	r := fs.String("role", store.RoleViewer, "admin (manage targets and scans) or viewer (read only)")
	a := fs.String("as", c.defaultActor, "requester recorded in the audit log")
	pos, err = parse(fs, args, 1)
	return *o, *r, *a, pos, err
}

func (c cli) userAdd(ctx context.Context, args []string) error {
	orgRef, role, actor, pos, err := c.userFlags("user add", args)
	if err != nil {
		return err
	}
	if role != store.RoleAdmin && role != store.RoleViewer {
		return fmt.Errorf("%w: -role must be admin or viewer", errUsage)
	}
	org, _, _, err := c.openOrg(ctx, orgRef)
	if err != nil {
		return err
	}
	u, err := c.admin.CreateUser(ctx, pos[0])
	if err != nil {
		return err
	}
	if err := c.admin.SetMembership(ctx, u.ID, org.ID, role, actor); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "user %s created, %s of %s\n", u.Email, role, org.Name)
	return c.printSetupToken(ctx, u, actor)
}

func (c cli) userMember(ctx context.Context, args []string) error {
	orgRef, role, actor, pos, err := c.userFlags("user member", args)
	if err != nil {
		return err
	}
	org, _, _, err := c.openOrg(ctx, orgRef)
	if err != nil {
		return err
	}
	u, err := c.admin.UserByEmail(ctx, pos[0])
	if err != nil {
		return err
	}
	if err := c.admin.SetMembership(ctx, u.ID, org.ID, role, actor); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "%s is now %s of %s\n", u.Email, role, org.Name)
	return nil
}

func (c cli) userReset(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("user reset", flag.ContinueOnError)
	actor := fs.String("as", c.defaultActor, "requester recorded in the audit log")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	u, err := c.admin.UserByEmail(ctx, pos[0])
	if err != nil {
		return err
	}
	return c.printSetupToken(ctx, u, *actor)
}

// userResetMFA removes a user's second factor when they lost their phone
// and their recovery codes. Check who is asking before running it: it is
// the one way around MFA. The user then signs in with their password and
// must enrol again before using admin routes.
func (c cli) userResetMFA(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("user reset-mfa", flag.ContinueOnError)
	actor := fs.String("as", c.defaultActor, "requester recorded in the auth log")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	u, err := c.admin.UserByEmail(ctx, pos[0])
	if err != nil {
		return err
	}
	if err := c.admin.ResetMFA(ctx, u.ID, *actor); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "two-factor authentication of %s removed and every session closed; they must enrol again\n", u.Email)
	return nil
}

// printSetupToken issues a setup token and tells how to use it. The token
// is shown once; only its hash is stored.
func (c cli) printSetupToken(ctx context.Context, u store.User, actor string) error {
	token, err := c.admin.IssueSetupToken(ctx, u.ID, setupTokenTTL, actor)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.out, "one-time setup token for %s (valid %s, shown only once):\n  %s\n", u.Email, setupTokenTTL, token)
	fmt.Fprintln(c.out, "send it to the user over a trusted channel; they set their password on the")
	fmt.Fprintln(c.out, "dashboard page /setup-password, or with")
	fmt.Fprintln(c.out, `  POST /api/v1/auth/setup-password {"token": "...", "password": "..."}`)
	return nil
}

func (c cli) targetAdd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("target add", flag.ContinueOnError)
	orgRef := c.orgFlag(fs)
	rate := fs.Float64("rate", store.DefaultRatePerSec, "requests per second")
	exclusions := fs.String("exclusions", "", `JSON, e.g. {"ips": ["192.0.2.10"], "paths": ["/admin"]}`)
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	// Validate exclusions now, with the same parser the worker uses: a
	// target whose exclusions the worker cannot read would never be scanned.
	if _, err := gate.ParseExclusions(json.RawMessage(*exclusions)); err != nil {
		return err
	}
	org, st, _, err := c.openOrg(ctx, *orgRef)
	if err != nil {
		return err
	}
	t, err := st.CreateTarget(ctx, store.NewTarget{
		Domain: pos[0], Exclusions: json.RawMessage(*exclusions), RatePerSec: *rate,
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(c.out, "target %s created in %s (id %s, %g req/s, not verified)\n", t.Domain, org.Name, t.ID, t.RatePerSec)
	return nil
}

func (c cli) targetShow(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("target show", flag.ContinueOnError)
	orgRef := c.orgFlag(fs)
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	org, st, _, err := c.openOrg(ctx, *orgRef)
	if err != nil {
		return err
	}
	t, err := st.TargetByDomain(ctx, pos[0])
	if err != nil {
		return err
	}
	verified := "no"
	switch {
	case t.Verified():
		verified = "yes, since " + t.VerifiedAt.Format(time.RFC3339)
		if t.VerifyCheckedAt != nil {
			verified += ", last checked " + t.VerifyCheckedAt.Format(time.RFC3339)
		}
	case t.VerifyToken != "" && t.VerifyTokenExpiresAt != nil:
		verified = "no, token pending until " + t.VerifyTokenExpiresAt.Format(time.RFC3339)
	}
	sched := "none (on demand only)"
	if s := t.Schedule; s != nil {
		sched = fmt.Sprintf("%s, weekday %s, %02d:00 %s, modules %s; next %s", s.Frequency, s.Weekday, s.Hour, s.TimeZone,
			strings.Join(s.Modules, ", "), s.NextScanAt.Format(time.RFC3339))
	}
	w := tabwriter.NewWriter(c.out, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "domain\t%s\norganization\t%s\nid\t%s\nverified\t%s\nrate\t%g req/s\nexclusions\t%s\nschedule\t%s\ncreated\t%s\n",
		t.Domain, org.Name, t.ID, verified, t.RatePerSec, t.Exclusions, sched, t.CreatedAt.Format(time.RFC3339))
	return w.Flush()
}

func (c cli) verifyToken(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("target verify-token", flag.ContinueOnError)
	orgRef := c.orgFlag(fs)
	actor := fs.String("as", c.defaultActor, "requester recorded in the audit log")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	_, st, verifier, err := c.openOrg(ctx, *orgRef)
	if err != nil {
		return err
	}
	t, err := st.TargetByDomain(ctx, pos[0])
	if err != nil {
		return err
	}
	in, err := verifier.Instructions(ctx, t.ID, *actor)
	if err != nil {
		return err
	}
	if in.Verified {
		fmt.Fprintf(c.out, "%s is already verified. Keep this record published:\n", in.Domain)
	} else {
		fmt.Fprintf(c.out, "To prove you control %s, publish this DNS record:\n", in.Domain)
	}
	w := tabwriter.NewWriter(c.out, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "  name\t%s\n  type\tTXT\n  value\t%s\n", in.RecordName, in.RecordValue)
	if err := w.Flush(); err != nil {
		return err
	}
	if in.ExpiresAt != nil {
		orgArg := ""
		if *orgRef != c.defaultOrg {
			orgArg = "-org " + *orgRef + " "
		}
		fmt.Fprintf(c.out, "Then run: orusctl target verify %s%s (before %s)\n", orgArg, in.Domain, in.ExpiresAt.Format(time.RFC3339))
	}
	return nil
}

func (c cli) verify(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("target verify", flag.ContinueOnError)
	orgRef := c.orgFlag(fs)
	actor := fs.String("as", c.defaultActor, "requester recorded in the audit log")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	_, st, verifier, err := c.openOrg(ctx, *orgRef)
	if err != nil {
		return err
	}
	t, err := st.TargetByDomain(ctx, pos[0])
	if err != nil {
		return err
	}
	if err := verifier.Verify(ctx, t.ID, *actor); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "%s is verified: active modules may now run on it.\n", t.Domain)
	fmt.Fprintln(c.out, "Keep the record published: it is checked again before active scans.")
	return nil
}

func (c cli) scan(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	orgRef := c.orgFlag(fs)
	actor := fs.String("as", c.defaultActor, "requester recorded in the audit log")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	modules := pos[1:]
	if len(modules) == 0 {
		modules = c.modules
	}
	for _, m := range modules {
		if !slices.Contains(c.modules, m) {
			return fmt.Errorf("unknown module %q (available: %s)", m, strings.Join(c.modules, ", "))
		}
	}
	_, st, _, err := c.openOrg(ctx, *orgRef)
	if err != nil {
		return err
	}
	t, err := st.TargetByDomain(ctx, pos[0])
	if err != nil {
		return err
	}
	sc, err := st.EnqueueScan(ctx, t.ID, modules, *actor)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.out, "scan %s queued for %s (modules: %s)\n", sc.ID, t.Domain, strings.Join(modules, ", "))
	if !t.Verified() {
		fmt.Fprintln(c.out, "note: target not verified, active modules will be refused")
	}
	return nil
}

func (c cli) status(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	orgRef := c.orgFlag(fs)
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	_, st, _, err := c.openOrg(ctx, *orgRef)
	if err != nil {
		return err
	}
	sc, err := st.GetScan(ctx, pos[0])
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(c.out, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "scan\t%s\ndomain\t%s\nstatus\t%s\nmodules\t%s\nrequested by\t%s\nattempts\t%d\n",
		sc.ID, sc.Domain, sc.Status, strings.Join(sc.Modules, ", "), sc.RequestedBy, sc.Attempt)
	if sc.Error != "" {
		fmt.Fprintf(w, "errors\t%s\n", sc.Error)
	}
	return w.Flush()
}

func (c cli) findings(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("findings", flag.ContinueOnError)
	orgRef := c.orgFlag(fs)
	verbose := fs.Bool("v", false, "show description, evidence, remediation and history")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	_, st, _, err := c.openOrg(ctx, *orgRef)
	if err != nil {
		return err
	}
	t, err := st.TargetByDomain(ctx, pos[0])
	if err != nil {
		return err
	}
	findings, err := st.ListFindings(ctx, t.ID)
	if err != nil {
		return err
	}
	if len(findings) == 0 {
		fmt.Fprintln(c.out, "no findings")
		return nil
	}
	if *verbose {
		for _, f := range findings {
			fmt.Fprintf(c.out, "[%s] %s (%s)\n  %s / %s, %s\n  %s\n", f.Severity, f.Title, f.Status,
				f.ModuleID, f.CheckID, f.Asset, f.Description)
			if f.Evidence != "" {
				fmt.Fprintf(c.out, "  evidence:\n    %s\n", strings.ReplaceAll(f.Evidence, "\n", "\n    "))
			}
			for i, step := range f.Remediation {
				fmt.Fprintf(c.out, "  fix %d: %s\n", i+1, step)
			}
			events, err := st.FindingHistory(ctx, t.ID, f.ID)
			if err != nil {
				return err
			}
			var history []string
			for _, e := range events {
				history = append(history, e.Kind()+" "+e.At.Format(time.DateOnly))
			}
			if len(history) > 0 {
				fmt.Fprintf(c.out, "  history: %s\n", strings.Join(history, ", "))
			}
			fmt.Fprintln(c.out)
		}
		return nil
	}
	w := tabwriter.NewWriter(c.out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SEVERITY\tSTATUS\tCHECK\tASSET\tTITLE")
	for _, f := range findings {
		status := string(f.Status)
		if f.FixedAt != nil {
			status += " " + f.FixedAt.Format(time.DateOnly)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", f.Severity, status, f.CheckID, f.Asset, f.Title)
	}
	return w.Flush()
}

func (c cli) assets(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("assets", flag.ContinueOnError)
	orgRef := c.orgFlag(fs)
	all := fs.Bool("all", false, "include assets no module sees any more")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	_, st, _, err := c.openOrg(ctx, *orgRef)
	if err != nil {
		return err
	}
	t, err := st.TargetByDomain(ctx, pos[0])
	if err != nil {
		return err
	}
	assets, err := st.ListAssets(ctx, t.ID, *all)
	if err != nil {
		return err
	}
	if len(assets) == 0 {
		fmt.Fprintln(c.out, "no assets (run a scan first)")
		return nil
	}
	w := tabwriter.NewWriter(c.out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "KIND\tVALUE\tSEEN BY\tFIRST SEEN\tLAST SEEN\tDETAILS")
	for _, a := range assets {
		seenBy := strings.Join(a.Sources, ",")
		if a.GoneAt != nil {
			seenBy = "gone " + a.GoneAt.Format(time.DateOnly)
		}
		var details []string
		for _, k := range slices.Sorted(maps.Keys(a.Details)) {
			details = append(details, k+"="+a.Details[k])
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", a.Kind, a.Value, seenBy,
			a.FirstSeen.Format(time.DateOnly), a.LastSeen.Format(time.DateOnly), strings.Join(details, " "))
	}
	return w.Flush()
}

// postureHistory is how many snapshots the posture command shows.
const postureHistory = 10

func (c cli) posture(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("posture", flag.ContinueOnError)
	orgRef := c.orgFlag(fs)
	verbose := fs.Bool("v", false, "list every check with its status")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	_, st, _, err := c.openOrg(ctx, *orgRef)
	if err != nil {
		return err
	}
	t, err := st.TargetByDomain(ctx, pos[0])
	if err != nil {
		return err
	}
	snaps, err := st.PostureHistory(ctx, t.ID, postureHistory)
	if err != nil {
		return err
	}
	if len(snaps) == 0 {
		fmt.Fprintln(c.out, "no posture yet (run a scan first)")
		return nil
	}
	last := snaps[0].Details
	fmt.Fprintf(c.out, "score: %s  (%d passed, %d failed, %d not applicable)\n",
		scoreText(last.Score), last.Total.Passed, last.Total.Failed, last.Total.NotApplicable)
	cats := last.CategoryScores()
	for _, cat := range slices.Sorted(maps.Keys(last.ByCategory)) {
		tally := last.ByCategory[cat]
		score := "n/a"
		if s, ok := cats[cat]; ok {
			score = fmt.Sprint(s)
		}
		fmt.Fprintf(c.out, "  %-8s %3s  (%d passed, %d failed)\n", cat, score, tally.Passed, tally.Failed)
	}
	if len(last.FailedChecks) > 0 {
		fmt.Fprintf(c.out, "failed: %s\n", strings.Join(last.FailedChecks, ", "))
	}
	var history []string
	for _, s := range slices.Backward(snaps) {
		history = append(history, s.At.Format(time.DateOnly)+" "+scoreText(s.Score))
	}
	fmt.Fprintf(c.out, "history: %s\n", strings.Join(history, ", "))

	if !*verbose {
		return nil
	}
	states, err := st.CheckStatuses(ctx, t.ID)
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(c.out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "\nCHECK\tMODULE\tSEVERITY\tSTATUS\tEVALUATED")
	for _, s := range states {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", s.CheckID, s.ModuleID, s.Severity, s.Status, s.EvaluatedAt.Format(time.DateOnly))
	}
	return w.Flush()
}

func scoreText(score *int) string {
	if score == nil {
		return "none"
	}
	return fmt.Sprintf("%d/100", *score)
}

func (c cli) audit(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	orgRef := c.orgFlag(fs)
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	_, st, _, err := c.openOrg(ctx, *orgRef)
	if err != nil {
		return err
	}
	entries, err := st.AuditLog(ctx, pos[0])
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(c.out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "AT\tACTOR\tACTION\tDETAILS")
	for _, e := range entries {
		details, _ := e.Details.(json.RawMessage)
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", e.At.Format(time.RFC3339), e.Actor, e.Action, details)
	}
	return w.Flush()
}

// offerIDs maps the names an operator types to plan IDs: the dashboard's
// French names and the IDs themselves.
var offerIDs = map[string]plan.ID{
	"gratuit": plan.Discovery, "discovery": plan.Discovery,
	"essentiel": plan.SME, "sme": plan.SME,
	"pro":       plan.Pro,
	"sur-devis": plan.Enterprise, "enterprise": plan.Enterprise,
}

// orgPlan shows an organization's offer, or sets it by hand: contracts,
// bank transfers, Mobile Money paid outside the product, until a payment
// provider updates subscriptions itself. Without -until or -trial the
// offer has no end.
func (c cli) orgPlan(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("org plan", flag.ContinueOnError)
	orgRef := c.orgFlag(fs)
	until := fs.String("until", "", "last day of the paid period, YYYY-MM-DD (UTC)")
	trial := fs.Int("trial", 0, "a trial of this many days instead of a paid period")
	actor := fs.String("as", c.defaultActor, "requester recorded in the audit log")
	pos, err := parse(fs, args, 0)
	if err != nil {
		return err
	}
	org, _, _, err := c.openOrg(ctx, *orgRef)
	if err != nil {
		return err
	}
	now := time.Now()
	if len(pos) == 0 {
		sub, err := c.admin.SubscriptionOf(ctx, org.ID)
		if err != nil {
			return err
		}
		eff := plan.Resolve(sub, now)
		status := "none (free offer)"
		if sub != nil {
			status = string(sub.Status)
		}
		fmt.Fprintf(c.out, "%s: offer %s (%s), subscription %s", org.Name, eff.Plan.Name, eff.Plan.ID, status)
		if eff.Until != nil {
			fmt.Fprintf(c.out, ", until %s", eff.Until.UTC().Format(time.DateOnly))
		}
		if eff.InGrace {
			fmt.Fprint(c.out, " (grace days)")
		}
		if eff.Lapsed {
			fmt.Fprint(c.out, " (lapsed)")
		}
		fmt.Fprintln(c.out)
		return nil
	}
	id, ok := offerIDs[strings.ToLower(pos[0])]
	if !ok {
		return fmt.Errorf("%w: unknown offer %q (gratuit, essentiel, pro, sur-devis)", errUsage, pos[0])
	}
	if *until != "" && *trial != 0 {
		return fmt.Errorf("%w: -until and -trial exclude each other", errUsage)
	}
	sub := plan.Subscription{Plan: id, Status: plan.Active}
	switch {
	case *trial < 0 || *trial > 90:
		return fmt.Errorf("%w: -trial must be 1 to 90 days", errUsage)
	case *trial > 0:
		end := now.AddDate(0, 0, *trial)
		sub.Status, sub.TrialEndsAt = plan.Trialing, &end
	case *until != "":
		day, err := time.Parse(time.DateOnly, *until)
		if err != nil {
			return fmt.Errorf("%w: -until: want YYYY-MM-DD", errUsage)
		}
		end := day.AddDate(0, 0, 1) // the whole last day
		if !end.After(now) {
			return fmt.Errorf("%w: -until is in the past", errUsage)
		}
		sub.PeriodEnd = &end
	}
	if err := c.admin.SetSubscription(ctx, org.ID, sub, "manual", *actor); err != nil {
		return err
	}
	p, _ := plan.Get(id)
	fmt.Fprintf(c.out, "%s: offer %s set", org.Name, p.Name)
	switch {
	case sub.TrialEndsAt != nil:
		fmt.Fprintf(c.out, ", trial until %s", sub.TrialEndsAt.UTC().Format(time.DateOnly))
	case sub.PeriodEnd != nil:
		fmt.Fprintf(c.out, ", paid until %s", *until)
	default:
		fmt.Fprint(c.out, ", without end")
	}
	fmt.Fprintln(c.out)
	return nil
}
