package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"
)

// The documented response schemas must match what the server sends: every
// read operation is called with a key and its JSON answer is checked
// against its schema (required fields present, types right, no field the
// document does not describe). This keeps the API reference honest for
// the people who build on it.
func TestOpenAPIResponsesMatchTheirSchemas(t *testing.T) {
	var spec struct {
		Paths      map[string]map[string]json.RawMessage `json:"paths"`
		Components struct {
			Schemas map[string]json.RawMessage `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(openAPISpec, &spec); err != nil {
		t.Fatalf("openapi.json: %v", err)
	}
	v := schemaChecker{defs: spec.Components.Schemas}

	e := newEnv(t)
	a := e.tenant("A", "example.com")
	_, read := e.newKey(a.orgID, a.session, "read")
	ids := strings.NewReplacer("{org}", a.orgID, "{target}", a.target.ID, "{finding}", a.finding.ID, "{scan}", a.scanID)

	for path, ops := range spec.Paths {
		raw, ok := ops["get"]
		if !ok {
			continue
		}
		var op struct {
			Responses map[string]struct {
				Content map[string]struct {
					Schema json.RawMessage `json:"schema"`
				} `json:"content"`
			} `json:"responses"`
		}
		if err := json.Unmarshal(raw, &op); err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		ct, ok := op.Responses["200"].Content["application/json"]
		if !ok || ct.Schema == nil {
			continue // not JSON (the PDF report)
		}
		got := e.keyDo("GET", "/api/v1"+ids.Replace(path), read, nil)
		if got.status != http.StatusOK {
			t.Errorf("GET %s = %d %s", path, got.status, got.body)
			continue
		}
		var body any
		if err := json.Unmarshal(got.body, &body); err != nil {
			t.Errorf("GET %s: not JSON: %v", path, err)
			continue
		}
		if m, ok := body.(map[string]any); ok {
			if items, ok := m["items"].([]any); ok && len(items) == 0 {
				t.Logf("GET %s: empty list, its items are not checked here", path)
			}
		}
		for _, problem := range v.check(ct.Schema, body, "$") {
			t.Errorf("GET %s: %s", path, problem)
		}
	}
}

// schemaChecker checks a JSON value against the subset of JSON Schema the
// document uses: $ref, type (one or a list, "null" included), properties,
// required, items, enum. Unknown keywords are ignored.
type schemaChecker struct {
	defs map[string]json.RawMessage
}

type schemaNode struct {
	Ref        string                     `json:"$ref"`
	Type       json.RawMessage            `json:"type"`
	Properties map[string]json.RawMessage `json:"properties"`
	Required   []string                   `json:"required"`
	Items      json.RawMessage            `json:"items"`
	Enum       []any                      `json:"enum"`
	// AdditionalProperties set means a map: its keys are not listed.
	AdditionalProperties json.RawMessage `json:"additionalProperties"`
}

func (c schemaChecker) check(raw json.RawMessage, value any, at string) []string {
	var s schemaNode
	if err := json.Unmarshal(raw, &s); err != nil {
		return []string{fmt.Sprintf("%s: unreadable schema: %v", at, err)}
	}
	if s.Ref != "" {
		def, ok := c.defs[strings.TrimPrefix(s.Ref, "#/components/schemas/")]
		if !ok {
			return []string{fmt.Sprintf("%s: unknown $ref %s", at, s.Ref)}
		}
		return c.check(def, value, at)
	}
	var types []string
	if len(s.Type) > 0 {
		var one string
		if json.Unmarshal(s.Type, &one) == nil {
			types = []string{one}
		} else {
			_ = json.Unmarshal(s.Type, &types)
		}
	}
	if len(types) > 0 && !typeMatches(types, value) {
		return []string{fmt.Sprintf("%s: %s, want %s", at, typeName(value), strings.Join(types, " or "))}
	}
	if len(s.Enum) > 0 && value != nil {
		found := false
		for _, e := range s.Enum {
			if e == value {
				found = true
			}
		}
		if !found {
			return []string{fmt.Sprintf("%s: %v not in %v", at, value, s.Enum)}
		}
	}
	var out []string
	switch v := value.(type) {
	case map[string]any:
		for _, r := range s.Required {
			if _, ok := v[r]; !ok {
				out = append(out, fmt.Sprintf("%s: required field %q missing", at, r))
			}
		}
		if s.Properties != nil && s.AdditionalProperties == nil {
			keys := make([]string, 0, len(v))
			for k := range v {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				ps, ok := s.Properties[k]
				if !ok {
					out = append(out, fmt.Sprintf("%s: field %q is not documented", at, k))
					continue
				}
				out = append(out, c.check(ps, v[k], at+"."+k)...)
			}
		}
	case []any:
		if s.Items != nil {
			for i, item := range v {
				out = append(out, c.check(s.Items, item, fmt.Sprintf("%s[%d]", at, i))...)
			}
		}
	}
	return out
}

func typeMatches(types []string, v any) bool {
	for _, t := range types {
		switch t {
		case "null":
			if v == nil {
				return true
			}
		case "object":
			if _, ok := v.(map[string]any); ok {
				return true
			}
		case "array":
			if _, ok := v.([]any); ok {
				return true
			}
		case "string":
			if _, ok := v.(string); ok {
				return true
			}
		case "boolean":
			if _, ok := v.(bool); ok {
				return true
			}
		case "number":
			if _, ok := v.(float64); ok {
				return true
			}
		case "integer":
			if f, ok := v.(float64); ok && f == float64(int64(f)) {
				return true
			}
		}
	}
	return false
}

func typeName(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case map[string]any:
		return "object"
	case []any:
		return "array"
	case string:
		return "string"
	case bool:
		return "boolean"
	case float64:
		return "number"
	}
	return fmt.Sprintf("%T", v)
}
