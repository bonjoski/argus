package service

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"bonjoski/argus/internal/cache"
	"bonjoski/argus/internal/heuristics"
	"bonjoski/argus/internal/inspector"
	"bonjoski/argus/internal/model"
	"bonjoski/argus/internal/registry"
	"bonjoski/argus/internal/singleflight"
	"bonjoski/argus/internal/vcs"
)

type VettingService struct {
	cache      cache.Store
	adapters   map[model.Ecosystem]registry.Adapter
	vcs        vcs.Verifier
	evaluator  heuristics.Evaluator
	defaultTTL time.Duration
	flight     singleflight.Group[*model.RiskReport]
}

func NewVettingService(
	cacheStore cache.Store,
	adapters []registry.Adapter,
	vcsVerifier vcs.Verifier,
	evaluator heuristics.Evaluator,
	ttl time.Duration,
) *VettingService {
	adapterMap := make(map[model.Ecosystem]registry.Adapter)
	for _, a := range adapters {
		adapterMap[a.Ecosystem()] = a
	}

	if ttl <= 0 {
		ttl = 24 * time.Hour
	}

	return &VettingService{
		cache:      cacheStore,
		adapters:   adapterMap,
		vcs:        vcsVerifier,
		evaluator:  evaluator,
		defaultTTL: ttl,
	}
}

// Vet coordinates the full pre-flight verification pipeline.
func (s *VettingService) Vet(ctx context.Context, eco model.Ecosystem, pkgName, version string) (*model.RiskReport, error) {
	return s.VetWithIntegrity(ctx, eco, pkgName, version, "")
}

// VetWithIntegrity coordinates pre-flight verification while binding cache lookups and
// stored verdicts to the concrete artifact IntegrityHash (ARG-04).
func (s *VettingService) VetWithIntegrity(ctx context.Context, eco model.Ecosystem, pkgName, version, expectedIntegrity string) (*model.RiskReport, error) {
	start := time.Now()

	// 1. Stage 0: Cache Check (bound to expectedIntegrity when provided)
	if s.cache != nil && version != "" && version != "latest" {
		if cachedReport, _, hit, err := s.cache.GetReportWithIntegrity(ctx, eco, pkgName, version, expectedIntegrity); err == nil && hit {
			cloned := cloneRiskReport(cachedReport)
			cloned.Cached = true
			cloned.LatencyMs = time.Since(start).Milliseconds()
			return cloned, nil
		}
	}

	flightKey := fmt.Sprintf("%s:%s@%s#%s", eco, pkgName, version, expectedIntegrity)
	shared, err, _ := s.flight.Do(flightKey, func() (*model.RiskReport, error) {
		return s.vetUncached(ctx, start, eco, pkgName, version, expectedIntegrity)
	})
	if err != nil {
		return nil, err
	}
	return cloneRiskReport(shared), nil
}

func (s *VettingService) vetUncached(ctx context.Context, start time.Time, eco model.Ecosystem, pkgName, version, expectedIntegrity string) (*model.RiskReport, error) {
	adapter, ok := s.adapters[eco]
	if !ok {
		return nil, fmt.Errorf("unsupported ecosystem: %s", eco)
	}

	// 2. Stage 1: Registry Metadata Fetch
	prov, etag, err := adapter.FetchProvenance(ctx, pkgName, version)
	if err != nil {
		return nil, fmt.Errorf("registry resolution failed: %w", err)
	}

	if expectedIntegrity != "" && prov.IntegrityHash != "" && eco != model.EcosystemPyPI && prov.IntegrityHash != expectedIntegrity {
		return nil, fmt.Errorf("package %s@%s integrity mismatch: expected %s, registry reported %s",
			pkgName, prov.ResolvedVersion, expectedIntegrity, prov.IntegrityHash)
	}

	// 3. Stage 2: Fan-Out Parallel Probes (VCS Verification & Pre-Flight AST Inspection)
	var wg sync.WaitGroup
	var subProbeDegraded atomic.Bool

	if prov.RepositoryURL == "" {
		prov.VCSStatus = model.VCSStatusNone
	} else if s.vcs != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			vcsCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
			defer cancel()

			res, vcsErr := s.vcs.Verify(vcsCtx, eco, prov.Name, prov.RepositoryURL)
			if vcsErr != nil || res == nil {
				subProbeDegraded.Store(true)
				prov.VCSStatus = model.VCSStatusInconclusive
				return
			}
			prov.VCSStatus = res.Status
			prov.RepositoryManifestName = res.ManifestName
			prov.RepositoryAgeMonths = res.AgeMonths
			prov.RepositoryCommitsCount = res.CommitsCount
		}()
	}

	// If package declares install scripts, AST inspection MUST succeed before caching an ALLOW verdict
	if prov.HasInstallScripts {
		if prov.TarballURL == "" {
			subProbeDegraded.Store(true)
		} else {
			wg.Add(1)
			go func() {
				defer wg.Done()
				inspCtx, cancel := context.WithTimeout(ctx, 600*time.Millisecond)
				defer cancel()

				insp := inspector.New(nil)
				res, inspErr := insp.InspectURL(inspCtx, prov.TarballURL)
				if inspErr != nil || res == nil {
					subProbeDegraded.Store(true)
					return
				}
				if res.IsDangerous {
					prov.HasSuspiciousAST = true
					for _, f := range res.Findings {
						prov.SuspiciousFindings = append(prov.SuspiciousFindings,
							fmt.Sprintf("%s:%d: [%s] %s", f.File, f.Line, f.Category, f.Snippet))
					}
				}
			}()
		}
	}
	wg.Wait()

	// 4. Stage 3: In-Memory Scoring Evaluation
	report := s.evaluator.Evaluate(prov)
	report.IntegrityHash = prov.IntegrityHash
	report.LatencyMs = time.Since(start).Milliseconds()
	report.Cached = false

	// 5. Cache the Result ONLY if sub-probes did not time out / degrade on an ALLOW verdict (ARG-04)
	isAllowOrWarn := !report.Blocked && report.TotalScore < 50 && report.RiskLevel != model.RiskLevelCritical
	if s.cache != nil && report.ResolvedVersion != "" && !(subProbeDegraded.Load() && isAllowOrWarn) {
		_ = s.cache.SetReport(ctx, report, etag, s.defaultTTL)
		_ = s.cache.SetProvenance(ctx, prov, etag, s.defaultTTL)
	}

	return report, nil
}

func cloneRiskReport(src *model.RiskReport) *model.RiskReport {
	if src == nil {
		return nil
	}
	cp := *src
	if len(src.Penalties) > 0 {
		cp.Penalties = append([]model.HeuristicFinding(nil), src.Penalties...)
	}
	if len(src.Offsets) > 0 {
		cp.Offsets = append([]model.MitigatingOffsetFinding(nil), src.Offsets...)
	}
	if len(src.Provenance.SuspiciousFindings) > 0 {
		cp.Provenance.SuspiciousFindings = append([]string(nil), src.Provenance.SuspiciousFindings...)
	}
	return &cp
}
