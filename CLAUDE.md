# Claude Code Guidelines for `argus`


## Build & Test Commands
- **Build CLI & Shim:** `go build -o bin/argus ./cmd/argus && go build -o bin/argus-shim ./cmd/argus-shim`
- **Unit Tests:** `go test -v ./...`
- **Adversarial Tests:** `go test -v ./test/adversarial/...`
- **Linter:** `golangci-lint run`
- **Audit Package:** `./bin/argus audit --package <name> --verbose`
- **Diagnostics:** `./bin/argus doctor`

## Code Style & Architectural Invariants
- 100% local zero-SaaS evaluation: never transmit package queries or code to cloud APIs.
- Pre-flight AST interception: inspect commands before package managers perform network resolution.
- Cisco Project Quarry reputation format for package signatures and provenance.
- Real-time killswitch bus on `~/.argus/argus.sock` broadcasting SIGKILL alerts to Fabrial.

## Commit Invariants
- Mandatory cryptographic signing with GPG key `7BB5B44244E586B0` (`git commit -S`).
- Present diff and test output for explicit user sign-off before committing.
