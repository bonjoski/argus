package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"bonjoski/argus/internal/model"
)

type Reporter interface {
	Render(w io.Writer, report *model.RiskReport) error
}

type JSONReporter struct{}

func (r JSONReporter) Render(w io.Writer, report *model.RiskReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

type TTYReporter struct{}

func (r TTYReporter) Render(w io.Writer, report *model.RiskReport) error {
	var sb strings.Builder

	// Header
	headerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#FAFAFA")).
		Background(lipgloss.Color("#5A56E0")).
		Padding(0, 1)

	cacheBadge := ""
	if report.Cached {
		cacheBadge = lipgloss.NewStyle().Foreground(lipgloss.Color("#888888")).Render("(cached)")
	}

	sb.WriteString(fmt.Sprintf("%s %s %s\n\n",
		headerStyle.Render("ARGUS"),
		lipgloss.NewStyle().Bold(true).Render(fmt.Sprintf("%s:%s@%s", report.Ecosystem, report.Package, report.ResolvedVersion)),
		cacheBadge,
	))

	// Score Badge
	var badgeColor string
	switch report.RiskLevel {
	case model.RiskLevelLow:
		badgeColor = "#00D26A" // Green
	case model.RiskLevelMedium:
		badgeColor = "#FCD535" // Yellow
	case model.RiskLevelHigh:
		badgeColor = "#FF8000" // Orange
	default:
		badgeColor = "#F8312F" // Red
	}

	scoreBadgeStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#000000")).
		Background(lipgloss.Color(badgeColor)).
		Padding(0, 1)

	sb.WriteString(fmt.Sprintf("  Risk Score:  %s  (Penalties: +%d, Offsets: -%d)  [%dms]\n\n",
		scoreBadgeStyle.Render(fmt.Sprintf("%s %d/100", report.RiskLevel, report.TotalScore)),
		report.TotalPenalties,
		report.TotalOffsets,
		report.LatencyMs,
	))

	// Provenance Summary
	sb.WriteString(lipgloss.NewStyle().Bold(true).Underline(true).Render("Provenance Details:") + "\n")
	sb.WriteString(fmt.Sprintf("  • First Published:   %s\n", report.Provenance.FirstReleaseDate.Format("2006-01-02")))
	sb.WriteString(fmt.Sprintf("  • Total Releases:    %d\n", report.Provenance.TotalReleases))
	if report.Provenance.WeeklyDownloads > 0 {
		sb.WriteString(fmt.Sprintf("  • Weekly Downloads:  %d\n", report.Provenance.WeeklyDownloads))
	}
	sb.WriteString(fmt.Sprintf("  • VCS Repository:    %s [%s]\n", report.Provenance.RepositoryURL, report.Provenance.VCSStatus))
	if report.Provenance.IntegrityHash != "" {
		sb.WriteString(fmt.Sprintf("  • Integrity Hash:    %s\n", report.Provenance.IntegrityHash))
	}
	sb.WriteString("\n")

	// Penalties Triggered
	hasPenalties := false
	for _, p := range report.Penalties {
		if p.Triggered {
			hasPenalties = true
			break
		}
	}

	if hasPenalties {
		sb.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#F8312F")).Render("Threat Penalties Triggered:") + "\n")
		for _, p := range report.Penalties {
			if p.Triggered {
				sb.WriteString(fmt.Sprintf("  [+%2d pts] %-28s %s\n", p.Points, lipgloss.NewStyle().Bold(true).Render(p.Name), lipgloss.NewStyle().Faint(true).Render("("+p.RuleID+")")))
			}
		}
		sb.WriteString("\n")
	}

	// Mitigating Offsets Triggered
	hasOffsets := false
	for _, o := range report.Offsets {
		if o.Triggered {
			hasOffsets = true
			break
		}
	}

	if hasOffsets {
		sb.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00D26A")).Render("Reputational Offsets Applied:") + "\n")
		for _, o := range report.Offsets {
			if o.Triggered {
				sb.WriteString(fmt.Sprintf("  [-%2d pts] %-28s %s\n", o.Credits, lipgloss.NewStyle().Bold(true).Render(o.Name), lipgloss.NewStyle().Faint(true).Render("("+o.OffsetID+")")))
			}
		}
		sb.WriteString("\n")
	}

	// Recommendation
	switch report.RiskLevel {
	case model.RiskLevelLow:
		sb.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#00D26A")).Render("✔ Provenance verified. Safe to install.") + "\n")
	case model.RiskLevelMedium:
		sb.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#FCD535")).Render("⚠ Notice: Moderate risk indicators present. Review before executing.") + "\n")
	case model.RiskLevelHigh:
		sb.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#FF8000")).Render("⚡ Warning: Elevated risk detected. Use caution.") + "\n")
	default:
		sb.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#F8312F")).Render("⛔ CRITICAL RISK: Potential slopsquat or unverified package. Blocked.") + "\n")
	}

	_, err := fmt.Fprint(w, sb.String())
	return err
}
