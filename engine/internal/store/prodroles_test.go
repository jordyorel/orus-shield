package store

import (
	"io/fs"
	"os"
	"regexp"
	"testing"
)

// TestProdRolesListEveryRole: on a production server the schema owner
// cannot create roles (deploy/prod/postgres-roles.sql creates them ahead,
// as the superuser). A migration that creates a role missing from that file
// would fail the first deployment after it, with the worker down: catch it
// here instead.
func TestProdRolesListEveryRole(t *testing.T) {
	prod, err := os.ReadFile("../../../deploy/prod/postgres-roles.sql")
	if err != nil {
		t.Fatal(err)
	}
	created := regexp.MustCompile(`CREATE ROLE ([a-z_]+)`)
	files, err := fs.Glob(migrationFS, "migrations/*.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		sql, err := migrationFS.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range created.FindAllSubmatch(sql, -1) {
			if !regexp.MustCompile(`'` + string(m[1]) + `'`).Match(prod) {
				t.Errorf("%s creates role %s, missing from deploy/prod/postgres-roles.sql", f, m[1])
			}
		}
	}
}
