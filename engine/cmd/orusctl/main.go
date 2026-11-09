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
//	orusctl target add [-org ORG] [-rate N] [-exclusions JSON] <domain>
//	orusctl target show [-org ORG] <domain>
//	orusctl target verify-token [-org ORG] [-as NAME] <domain>
//	orusctl target verify [-org ORG] [-as NAME] <domain>
//	orusctl scan [-org ORG] [-as NAME] <domain> [module ...]
//	orusctl status [-org ORG] <scan-id>
//	orusctl findings [-org ORG] [-v] <domain>
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
	"github.com/jordyorel/orus-shield/engine/internal/resolver"
	"github.com/jordyorel/orus-shield/engine/internal/store"
)

const usage = `usage:
  orusctl org add [-as NAME] <name>
  orusctl org list
  orusctl target add [-org ORG] [-rate N] [-exclusions JSON] <domain>
  orusctl target show [-org ORG] <domain>
  orusctl target verify-token [-org ORG] [-as NAME] <domain>   (prints the DNS record to publish)
  orusctl target verify [-org ORG] [-as NAME] <domain>         (checks it)
  orusctl scan [-org ORG] [-as NAME] <domain> [module ...]   (default: every module)
  orusctl status [-org ORG] <scan-id>
  orusctl findings [-org ORG] [-v] <domain>
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
}

// OrgStore is the part of store.Org orusctl uses: everything about targets
// goes through an org-scoped handle, like the API.
type OrgStore interface {
	CreateTarget(ctx context.Context, nt store.NewTarget) (store.Target, error)
	TargetByDomain(ctx context.Context, domain string) (store.Target, error)
	EnqueueScan(ctx context.Context, targetID string, modules []string, requestedBy string) (store.Scan, error)
	GetScan(ctx context.Context, id string) (store.Scan, error)
	ListFindings(ctx context.Context, targetID string) ([]finding.Finding, error)
	FindingHistory(ctx context.Context, targetID, findingID string) ([]store.FindingEvent, error)
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
		reg, err := all.Registry()
		if err != nil {
			return err
		}
		var ids []string
		for _, m := range reg.All() {
			ids = append(ids, m.Info().ID)
		}
		c := cli{
			admin: st, openOrg: storeOpener(st),
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
func storeOpener(st *store.Store) OrgOpener {
	return func(ctx context.Context, ref string) (store.Organization, OrgStore, Verifier, error) {
		org, err := st.FindOrganization(ctx, ref)
		if err != nil {
			return store.Organization{}, nil, nil, err
		}
		h, err := st.Org(org.ID)
		if err != nil {
			return store.Organization{}, nil, nil, err
		}
		return org, h, ownership.New(h, resolver.NewSystem()), nil
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
			return fmt.Errorf("%w: org needs a subcommand (add, list)", errUsage)
		}
		switch rest[0] {
		case "add":
			return c.orgAdd(ctx, rest[1:])
		case "list":
			return c.orgList(ctx, rest[1:])
		}
		return fmt.Errorf("%w: unknown org subcommand %q", errUsage, rest[0])
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
	w := tabwriter.NewWriter(c.out, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "domain\t%s\norganization\t%s\nid\t%s\nverified\t%s\nrate\t%g req/s\nexclusions\t%s\ncreated\t%s\n",
		t.Domain, org.Name, t.ID, verified, t.RatePerSec, t.Exclusions, t.CreatedAt.Format(time.RFC3339))
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
