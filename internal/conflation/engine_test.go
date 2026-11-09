package conflation

import (
	"reflect"
	"testing"

	"bonjoski/argus/internal/model"
)

func TestTokenize(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{"express-auth-helpers", []string{"express", "auth", "helpers"}},
		{"fastapi_surrealdb", []string{"fastapi", "surrealdb"}},
		{"reactDom", []string{"react", "dom"}},
		{"@angular/core", []string{"core"}},
		{"pytest-tempo", []string{"pytest", "tempo"}},
	}

	for _, tc := range tests {
		actual := Tokenize(tc.input)
		if !reflect.DeepEqual(actual, tc.expected) {
			t.Errorf("Tokenize(%q) = %v, expected %v", tc.input, actual, tc.expected)
		}
	}
}

func TestLevenshteinDistance(t *testing.T) {
	tests := []struct {
		s1, s2   string
		expected int
	}{
		{"requests", "reqeusts", 2},
		{"lodash", "lodas", 1},
		{"colors", "colros", 2},
		{"express", "express", 0},
		{"a", "b", 1},
	}

	for _, tc := range tests {
		actual := levenshteinDistance(tc.s1, tc.s2)
		if actual != tc.expected {
			t.Errorf("levenshteinDistance(%q, %q) = %d, expected %d", tc.s1, tc.s2, actual, tc.expected)
		}
	}
}

func TestConflationEngine_Typosquatting(t *testing.T) {
	engine := NewEngine()

	// "reqeusts" is a typosquat of "requests" on PyPI
	res := engine.Evaluate("reqeusts", model.EcosystemPyPI)
	if !res.IsConflated || !res.IsTyposquat {
		t.Fatalf("expected reqeusts to be detected as typosquat: %+v", res)
	}
	if res.TargetPkg != "requests" {
		t.Errorf("expected target requests, got %s", res.TargetPkg)
	}

	// "lodas" is a typosquat of "lodash" on NPM
	resNPM := engine.Evaluate("lodas", model.EcosystemNPM)
	if !resNPM.IsConflated || !resNPM.IsTyposquat {
		t.Fatalf("expected lodas to be detected as typosquat: %+v", resNPM)
	}
}

func TestConflationEngine_TokenConflation(t *testing.T) {
	engine := NewEngine()

	// "express-auth-helpers" blends express + auth + helpers
	res := engine.Evaluate("express-auth-helpers", model.EcosystemNPM)
	if !res.IsConflated {
		t.Fatalf("expected express-auth-helpers to be detected as conflation: %+v", res)
	}

	// "ai-react-auth" blends ai + react + auth
	resReact := engine.Evaluate("ai-react-auth", model.EcosystemNPM)
	if !resReact.IsConflated {
		t.Fatalf("expected ai-react-auth to be detected as conflation: %+v", resReact)
	}
}

func TestConflationEngine_ApprovedNamespace(t *testing.T) {
	engine := NewEngine()

	// Registry-enforced organizational scopes (@types/*, @eslint/*) ARE exempt
	resTypes := engine.Evaluate("@types/express-auth-helpers", model.EcosystemNPM)
	if resTypes.IsConflated {
		t.Errorf("expected @types/express-auth-helpers to be exempt under @types/* org scope, got: %+v", resTypes)
	}

	// Unscoped public prefixes (pytest-*, eslint-plugin-*) MUST NOT grant exemption or -20 credit (ARG-06)
	resUnscopedPyPI := engine.Evaluate("pytest-fastapi-auth", model.EcosystemPyPI)
	if !resUnscopedPyPI.IsConflated {
		t.Errorf("expected unscoped pytest-fastapi-auth slopsquat to be flagged as conflated, got exempt")
	}

	resUnscopedNPM := engine.Evaluate("eslint-plugin-express-auth", model.EcosystemNPM)
	if !resUnscopedNPM.IsConflated {
		t.Errorf("expected unscoped eslint-plugin-express-auth slopsquat to be flagged as conflated, got exempt")
	}
}

func TestConflationEngine_AuthenticPackage(t *testing.T) {
	engine := NewEngine()

	// "express" is in the npm corpus, so it should not be flagged as conflated
	res := engine.Evaluate("express", model.EcosystemNPM)
	if res.IsConflated {
		t.Errorf("expected authentic express to not be conflated, got: %+v", res)
	}

	// "requests" is in the PyPI corpus
	resPyPI := engine.Evaluate("requests", model.EcosystemPyPI)
	if resPyPI.IsConflated {
		t.Errorf("expected authentic requests to not be conflated, got: %+v", resPyPI)
	}
}
