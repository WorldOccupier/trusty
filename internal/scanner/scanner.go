package scanner

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/WorldOccupier/trusty/internal/config"
	"github.com/WorldOccupier/trusty/internal/hallucination"
	"github.com/WorldOccupier/trusty/internal/llm"
	"github.com/WorldOccupier/trusty/internal/types"
)

type Scanner struct {
	cfg      *config.Config
	static   *StaticAnalyzer
	hallu    *hallucination.Detector
	semantic *SemanticAnalyzer
	verify   *VerificationEngine
	security *SecurityScanner
	logic    *LogicDetector
	cache    *ScanCache
}

func NewScanner(cfg *config.Config, llmProvider llm.Provider) *Scanner {
	return &Scanner{
		cfg:      cfg,
		static:   NewStaticAnalyzer(),
		hallu:    hallucination.NewDetector(),
		semantic: NewSemanticAnalyzer(llmProvider),
		verify:   NewVerificationEngine(),
		security: NewSecurityScanner(),
		logic:    NewLogicDetector(),
		cache:    NewScanCache(""),
	}
}

func (s *Scanner) Scan(ctx context.Context, opts types.DiffOptions) (*types.ScanResult, error) {
	start := time.Now()

	files, err := GetDiff(opts)
	if err != nil {
		return nil, fmt.Errorf("getting diff: %w", err)
	}

	if len(files) == 0 {
		return &types.ScanResult{
			Files:      nil,
			Timestamp:  start.UTC().Format(time.RFC3339),
			DurationMs: 0,
			TrustScore: 100,
			Summary: types.ScanSummary{
				FilesScanned: 0,
				Status:       "clean",
				TotalIssues:  0,
			},
		}, nil
	}

	enabledTiers := make(map[int]bool)
	for _, t := range s.cfg.Scan.Tiers {
		enabledTiers[t] = true
	}

	var fileResults []types.FileResult
	var mu sync.Mutex
	var wg sync.WaitGroup
	errCh := make(chan error, len(files))

	for _, file := range files {
		wg.Add(1)
		go func(f types.DiffFile) {
			defer wg.Done()

			if cachedFindings, cachedScore, ok := s.cache.Get(f.Path, f.Content); ok {
				mu.Lock()
				fileResults = append(fileResults, types.FileResult{
					Path:     f.Path,
					Language: f.Language,
					Findings: cachedFindings,
					Score:    cachedScore,
				})
				mu.Unlock()
				return
			}

			var findings []types.Finding

			if enabledTiers[1] {
				staticFindings := s.static.Analyze(f.Path, f.Content)
				findings = append(findings, staticFindings...)

				if s.hallu != nil {
					halluFindings := s.hallu.Detect(f.Path, f.Content, f.Diff)
					findings = append(findings, halluFindings...)
				}

				if s.security != nil {
					secFindings := s.security.Scan([]types.DiffFile{f})
					findings = append(findings, secFindings...)
				}

				if s.logic != nil {
					logicFindings := s.logic.Detect([]types.DiffFile{f})
					findings = append(findings, logicFindings...)
				}
			}

			if enabledTiers[2] && s.semantic != nil {
				semanticFindings, err := s.semantic.Analyze(ctx, f, "")
				if err != nil {
					errCh <- fmt.Errorf("semantic analysis of %s: %w", f.Path, err)
					return
				}
				findings = append(findings, semanticFindings...)
			}

			score := calculateScore(findings)

			s.cache.Set(f.Path, f.Content, findings, score)

			mu.Lock()
			fileResults = append(fileResults, types.FileResult{
				Path:     f.Path,
				Language: f.Language,
				Findings: findings,
				Score:    score,
			})
			mu.Unlock()
		}(file)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			return nil, err
		}
	}

	if enabledTiers[3] {
		verifyFindings, err := s.verify.Verify(ctx, files)
		if err == nil {
			for i, fr := range fileResults {
				for _, vf := range verifyFindings {
					if vf.Category == fr.Path {
						fileResults[i].Findings = append(fileResults[i].Findings, vf)
					}
				}
				fileResults[i].Score = calculateScore(fileResults[i].Findings)
			}
		}
	}

	totalIssues := 0
	totalErrors := 0
	totalWarnings := 0
	totalInfos := 0
	overallScore := 100

	for _, fr := range fileResults {
		totalIssues += len(fr.Findings)
		for _, f := range fr.Findings {
			switch f.Severity {
			case types.SeverityError:
				totalErrors++
			case types.SeverityWarning:
				totalWarnings++
			case types.SeverityInfo:
				totalInfos++
			}
		}
		if fr.Score < overallScore {
			overallScore = fr.Score
		}
	}

	duration := time.Since(start)

	status := "clean"
	if overallScore < s.cfg.Scan.MinScore {
		status = "failed"
	} else if totalIssues > 0 {
		status = "warning"
	}

	return &types.ScanResult{
		Files:      fileResults,
		Timestamp:  start.UTC().Format(time.RFC3339),
		DurationMs: duration.Milliseconds(),
		TrustScore: overallScore,
		Summary: types.ScanSummary{
			TotalIssues:  totalIssues,
			Errors:       totalErrors,
			Warnings:     totalWarnings,
			Info:         totalInfos,
			FilesScanned: len(fileResults),
			Duration:     duration.Round(time.Millisecond).String(),
			Status:       status,
			MinScore:     s.cfg.Scan.MinScore,
		},
	}, nil
}

func (s *Scanner) SetCacheEnabled(enabled bool) {
	s.cache.SetEnabled(enabled)
}

func (s *Scanner) FlushCache() {
	s.cache.Flush()
}

func calculateScore(findings []types.Finding) int {
	if len(findings) == 0 {
		return 100
	}

	penalty := 0
	for _, f := range findings {
		switch f.Severity {
		case types.SeverityError:
			penalty += 15
		case types.SeverityWarning:
			penalty += 7
		case types.SeverityInfo:
			penalty += 3
		}
	}

	score := 100 - penalty
	if score < 0 {
		score = 0
	}
	return score
}
