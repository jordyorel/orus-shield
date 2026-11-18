package api

import (
	_ "embed"
	"net/http"
)

// openAPISpec documents the public API: the routes an API key may call
// (OpenAPI 3.1). It is built into the binary and served as is, so the
// documentation cannot drift from the server it comes with; the tests
// check that every documented operation answers.
//
//go:embed openapi.json
var openAPISpec []byte

// openAPI answers GET /api/v1/openapi.json, public: tools generate clients
// from it, and the dashboard's /docs/api page reads it.
func openAPI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(openAPISpec)
}
