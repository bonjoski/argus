package service

import (
	"context"
	"fmt"
	"sync"
	"time"

	"bonjoski/argus/internal/cache"
	"bonjoski/argus/internal/heuristics"
	"bonjoski/argus/internal/inspector"
	"bonjoski/argus/internal/model"
	"bonjoski/argus/internal/registry"
	"bonjoski/argus/internal/vcs"
)

type VettingService struct {
	cache      cache.Store
	adapters   map[model.Ecosystem]registry.Adapter
	vcs        vcs.Verifier
	evaluator  heuristics.Evaluator
	defaultTTL time.Duration
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
	start := time.Now()

	// 1. Stage 0: Cache Check
	if s.cache != nil && version != "" && version != "latest" {
		if cachedReport, _, hit, err := s.cache.GetReport(ctx, eco, pkgName, version); err == nil && hit {
			cachedReport.Cached = true
			cachedReport.LatencyMs = time.Since(start).Milliseconds()
			return cachedReport, nil
		}
	}

	adapter, ok := s.adapters[eco]
	if !ok {
		return nil, fmt.Errorf("unsupported ecosystem: %s", eco)
	}

	// 2. Stage 1: Registry Metadata Fetch
	prov, etag, err := adapter.FetchProvenance(ctx, pkgName, version)
	if err != nil {
		return nil, fmt.Errorf("registry resolution failed: %w", err)
	}

	// 3. Stage 2: Fan-Out Parallel Probes (VCS Verification & Pre-Flight AST Inspection)
	var wg sync.WaitGroup
	if prov.RepositoryURL == "" {
		prov.VCSStatus = model.VCSStatusNone
	} else if s.vcs != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			vcsCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
			defer cancel()

			res, err := s.vcs.Verify(vcsCtx, eco, prov.Name, prov.RepositoryURL)
			if err == nil && res != nil {
				prov.VCSStatus = res.Status
				prov.RepositoryManifestName = res.ManifestName
				prov.RepositoryAgeMonths = res.AgeMonths
				prov.RepositoryCommitsCount = res.CommitsCount
			}
		}()
	}

	// If package declares install scripts and has a tarball URL, inspect the tarball in parallel
	if prov.HasInstallScripts && prov.TarballURL != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			inspCtx, cancel := context.WithTimeout(ctx, 600*time.Millisecond)
			defer cancel()

			insp := inspector.New(nil)
			if res, err := insp.InspectURL(inspCtx, prov.TarballURL); err == nil && res != nil {
				if res.IsDangerous {
					prov.HasSuspiciousAST = true
					for _, f := range res.Findings {
						prov.SuspiciousFindings = append(prov.SuspiciousFindings,
							fmt.Sprintf("%s:%d: [%s] %s", f.File, f.Line, f.Category, f.Snippet))
					}
				}
			}
		}()
	}
	wg.Wait()

	// 4. Stage 3: In-Memory Scoring Evaluation
	report := s.evaluator.Evaluate(prov)
	report.LatencyMs = time.Since(start).Milliseconds()
	report.Cached = false

	// 5. Cache the Result (if cache is configured)
	if s.cache != nil && report.ResolvedVersion != "" {
		_ = s.cache.SetReport(ctx, report, etag, s.defaultTTL)
		_ = s.cache.SetProvenance(ctx, prov, etag, s.defaultTTL)
	}

	return report, nil
}
