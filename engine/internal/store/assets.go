package store

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/jordyorel/orus-shield/engine/internal/asset"
)

// Asset is one entry of a target's inventory.
type Asset struct {
	ID        string
	TargetID  string
	Kind      asset.Kind
	Value     string
	Details   map[string]string
	Sources   []string // modules that saw it in their last successful run
	FirstSeen time.Time
	LastSeen  time.Time
	GoneAt    *time.Time // set when no module sees it any more
}

// assetCounts summarizes what a scan changed in the inventory.
type assetCounts struct {
	reported, created, back, gone int
	unobserved                    int // not reported, but out of reach: kept as is
}

// saveAssets records the assets of a finished scan, inside FinishScan's
// transaction. Rules (see migration 0005):
//   - reported by module M: created, or last_seen moved and M added to its
//     sources; a gone asset seen again is back (gone_at cleared);
//   - not reported by M although M succeeded: M is removed from its sources;
//     with no source left, the asset is gone. Unless it was out of reach in
//     this scan (r.Unobserved): then it is left unchanged;
//   - modules that failed change nothing.
func saveAssets(ctx context.Context, tx pgx.Tx, orgID, targetID, domain string, at time.Time, r ScanResult) (assetCounts, error) {
	var c assetCounts
	for _, moduleID := range slices.Sorted(maps.Keys(r.Assets)) {
		if !slices.Contains(r.Succeeded, moduleID) {
			return c, fmt.Errorf("assets from module %s, which did not succeed", moduleID)
		}
	}

	for _, moduleID := range r.Succeeded {
		assets := r.Assets[moduleID]
		kinds := make([]string, 0, len(assets))
		values := make([]string, 0, len(assets))
		for _, a := range assets {
			// The worker validated them already; checking again here keeps
			// the store safe whoever calls it.
			if err := a.Validate(domain); err != nil {
				return c, fmt.Errorf("asset %s from %s: %w", a.Key(), moduleID, err)
			}
			details := a.Details
			if details == nil {
				details = map[string]string{}
			}
			data, err := json.Marshal(details)
			if err != nil {
				return c, fmt.Errorf("asset %s: encode details: %w", a.Key(), err)
			}
			// RETURNING old.* (PostgreSQL 18): all NULL for a new row.
			var created, back bool
			err = tx.QueryRow(ctx, `
				INSERT INTO assets AS a (org_id, target_id, kind, value, details, sources, first_seen, last_seen)
				VALUES ($1, $2, $3, $4, $5, ARRAY[$6::text], $7, $7)
				ON CONFLICT (target_id, kind, value) DO UPDATE SET
					details   = a.details || EXCLUDED.details,
					sources   = CASE WHEN $6 = ANY(a.sources) THEN a.sources ELSE a.sources || $6::text END,
					last_seen = EXCLUDED.last_seen,
					gone_at   = NULL
				RETURNING old.id IS NULL, old.gone_at IS NOT NULL`,
				orgID, targetID, string(a.Kind), a.Value, data, moduleID, at).Scan(&created, &back)
			if err != nil {
				return c, fmt.Errorf("save asset %s: %w", a.Key(), err)
			}
			if created {
				c.created++
			}
			if back {
				c.back++
			}
			c.reported++
			kinds = append(kinds, string(a.Kind))
			values = append(values, a.Value)
		}

		if r.Unobserved != nil {
			kept, err := unobservedAssets(ctx, tx, targetID, moduleID, kinds, values, r.Unobserved)
			if err != nil {
				return c, err
			}
			// Added to the "reported" lists only for the retirement query
			// below: their row is not updated.
			for _, a := range kept {
				kinds = append(kinds, string(a.Kind))
				values = append(values, a.Value)
			}
			c.unobserved += len(kept)
		}

		rows, err := tx.Query(ctx, `
			UPDATE assets a SET
				sources = array_remove(a.sources, $2),
				gone_at = CASE WHEN cardinality(array_remove(a.sources, $2)) = 0 THEN $5::timestamptz END
			WHERE a.target_id = $1 AND $2 = ANY(a.sources)
			  AND NOT EXISTS (
				SELECT 1 FROM unnest($3::text[], $4::text[]) AS r(kind, value)
				WHERE r.kind = a.kind AND r.value = a.value)
			RETURNING a.gone_at IS NOT NULL`,
			targetID, moduleID, kinds, values, at)
		if err != nil {
			return c, fmt.Errorf("retire assets of %s: %w", moduleID, err)
		}
		gone, err := pgx.CollectRows(rows, pgx.RowTo[bool])
		if err != nil {
			return c, fmt.Errorf("retire assets of %s: %w", moduleID, err)
		}
		for _, g := range gone {
			if g {
				c.gone++
			}
		}
	}
	return c, nil
}

// ListAssets returns the inventory of one of the organization's targets:
// current assets, plus gone ones when includeGone is set. Ordered by kind,
// then value.
func (o *Org) ListAssets(ctx context.Context, targetID string, includeGone bool) ([]Asset, error) {
	if !isUUID(targetID) {
		return nil, nil
	}
	tx, err := o.begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("list assets: %w", err)
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `
		SELECT id::text, target_id::text, kind, value, details, sources, first_seen, last_seen, gone_at
		FROM assets
		WHERE org_id = $1 AND target_id = $2 AND ($3 OR gone_at IS NULL)
		ORDER BY array_position(ARRAY['hostname','ip','service','certificate'], kind), value`,
		o.orgID, targetID, includeGone)
	if err != nil {
		return nil, fmt.Errorf("list assets: %w", err)
	}
	assets, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Asset, error) {
		var a Asset
		var kind string
		err := r.Scan(&a.ID, &a.TargetID, &kind, &a.Value, &a.Details, &a.Sources, &a.FirstSeen, &a.LastSeen, &a.GoneAt)
		a.Kind = asset.Kind(kind)
		return a, err
	})
	if err != nil {
		return nil, fmt.Errorf("list assets: %w", err)
	}
	return assets, tx.Commit(ctx)
}

// unobservedAssets returns the assets of moduleID that it did not report in
// this run (kinds and values are what it reported) but that were out of
// reach, so their absence proves nothing.
func unobservedAssets(ctx context.Context, tx pgx.Tx, targetID, moduleID string, kinds, values []string,
	unobserved func(asset.Kind, string) bool) ([]asset.Asset, error) {
	rows, err := tx.Query(ctx, `
		SELECT a.kind, a.value FROM assets a
		WHERE a.target_id = $1 AND $2 = ANY(a.sources)
		  AND NOT EXISTS (
			SELECT 1 FROM unnest($3::text[], $4::text[]) AS r(kind, value)
			WHERE r.kind = a.kind AND r.value = a.value)`,
		targetID, moduleID, kinds, values)
	if err != nil {
		return nil, fmt.Errorf("list assets not reported by %s: %w", moduleID, err)
	}
	candidates, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (asset.Asset, error) {
		var a asset.Asset
		var kind string
		err := row.Scan(&kind, &a.Value)
		a.Kind = asset.Kind(kind)
		return a, err
	})
	if err != nil {
		return nil, fmt.Errorf("list assets not reported by %s: %w", moduleID, err)
	}
	var kept []asset.Asset
	for _, a := range candidates {
		if unobserved(a.Kind, a.Value) {
			kept = append(kept, a)
		}
	}
	return kept, nil
}

// CurrentHostnames returns the hostnames of a target's inventory that are
// still current (not gone), sorted. The worker gives them to the modules of
// a scan (module.Target.Hosts). Cross-organization: worker only.
func (s *Store) CurrentHostnames(ctx context.Context, targetID string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT value FROM assets WHERE target_id = $1 AND kind = $2 AND gone_at IS NULL ORDER BY value`,
		targetID, string(asset.KindHostname))
	if err != nil {
		return nil, fmt.Errorf("current hostnames of %s: %w", targetID, err)
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("current hostnames of %s: %w", targetID, err)
	}
	return names, nil
}
