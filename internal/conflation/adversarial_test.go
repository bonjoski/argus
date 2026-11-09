package conflation

import (
	"testing"

	"bonjoski/argus/internal/model"
)

// ARG-06: Unscoped public prefixes and unverified @attacker scopes MUST NEVER grant IsApprovedNamespace credit.
func TestAdversarial_ARG06_UnscopedPrefixesNeverGrantNamespaceCredit(t *testing.T) {
	unscopedAttacks := []struct {
		eco  model.Ecosystem
		name string
	}{
		{model.EcosystemPyPI, "pytest-fastapi-auth"},
		{model.EcosystemPyPI, "flask-jwt-helper"},
		{model.EcosystemPyPI, "django-sso-agent"},
		{model.EcosystemNPM, "eslint-plugin-react-auth"},
		{model.EcosystemNPM, "babel-plugin-lodash-security"},
		{model.EcosystemNPM, "vite-plugin-express-jwt"},
		{model.EcosystemNPM, "rollup-plugin-axios-token"},
		{model.EcosystemNPM, "webpack-plugin-next-auth"},
		{model.EcosystemNPM, "webpack-react-helpers"},
		{model.EcosystemNPM, "@evil-attacker-org/express"},
		{model.EcosystemCargo, "cargo-tokio-auth"},
		{model.EcosystemNuGet, "Microsoft.FakeBackdoor.Auth"},
	}

	engine := NewEngine()
	for _, tc := range unscopedAttacks {
		if IsApprovedNamespace(tc.name, tc.eco) {
			t.Errorf("SECURITY BYPASS (ARG-06): %s package %q falsely granted IsApprovedNamespace!", tc.eco, tc.name)
		}
	}

	// Confirm legitimate registry-enforced org scopes DO still pass
	if !IsApprovedNamespace("@types/node", model.EcosystemNPM) {
		t.Errorf("expected @types/node to be recognized as verified org scope")
	}
	if !IsApprovedNamespace("@angular/core", model.EcosystemNPM) {
		t.Errorf("expected @angular/core to be recognized as verified org scope")
	}
	if !IsApprovedNamespace("golang.org/x/sys", model.EcosystemGo) {
		t.Errorf("expected golang.org/x/sys to be recognized as verified domain namespace")
	}

	// Confirm conflation engine flags unscoped prefix slopsquats
	res := engine.Evaluate("eslint-plugin-express-auth", model.EcosystemNPM)
	if !res.IsConflated {
		t.Errorf("expected eslint-plugin-express-auth to be flagged as conflated")
	}
}
