package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"bonjoski/argus/pkg/quarry"
)

var (
	testSequenceFile string
	testRulesPath    string
	testSocketPath   string
)

func newTestCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "test",
		Short: "Testing and validation tools for Argus runtime engines and policies",
	}

	cmd.AddCommand(newSimulateAttackCmd())
	return cmd
}

func newSimulateAttackCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "simulate-attack",
		Short: "Simulate a multi-step causal attack sequence against Quarry detection engine",
		RunE: func(cmd *cobra.Command, args []string) error {
			// 1. Resolve Rules
			rulesPath := testRulesPath
			if rulesPath == "" {
				// Try default candidates
				candidates := []string{
					"rules/quarry",
					"rules/quarry/agent_exfiltration_via_curl.yaml",
					filepath.Join(os.Getenv("HOME"), ".argus", "rules", "quarry"),
				}
				for _, c := range candidates {
					if _, err := os.Stat(c); err == nil {
						rulesPath = c
						break
					}
				}
			}

			if rulesPath == "" {
				return fmt.Errorf("no quarry rules found (specify --rules <path>)")
			}

			var rules []*quarry.Rule
			fi, err := os.Stat(rulesPath)
			if err != nil {
				return fmt.Errorf("failed to stat rules path %s: %w", rulesPath, err)
			}

			if fi.IsDir() {
				rules, err = quarry.LoadRulesFromDir(rulesPath)
			} else {
				r, loadErr := quarry.LoadRuleFromFile(rulesPath)
				if loadErr == nil {
					rules = []*quarry.Rule{r}
				}
				err = loadErr
			}
			if err != nil || len(rules) == 0 {
				return fmt.Errorf("failed to load quarry rules from %s: %w", rulesPath, err)
			}

			// 2. Initialize Correlator & Dispatcher
			correlator := quarry.NewCorrelator(quarry.CorrelatorOptions{
				MultiTierWindow: true,
			})

			for _, r := range rules {
				if err := correlator.RegisterRule(r); err != nil {
					return fmt.Errorf("failed to compile rule %q: %w", r.Name, err)
				}
			}

			sock := testSocketPath
			if sock == "" {
				sock = daemonSocketPath
			}
			dispatcher := quarry.NewDispatcher(sock)
			correlator.SetDispatcher(dispatcher)

			// 3. Load Sequence
			seqFile := testSequenceFile
			if seqFile == "" {
				seqCandidates := []string{
					"fixtures/exfiltration_sequence.json",
					"fixtures/exfiltration.json",
				}
				for _, sc := range seqCandidates {
					if _, err := os.Stat(sc); err == nil {
						seqFile = sc
						break
					}
				}
			}

			if seqFile == "" {
				return fmt.Errorf("no attack sequence file found (specify --sequence <path>)")
			}

			data, err := os.ReadFile(seqFile)
			if err != nil {
				return fmt.Errorf("failed to read sequence file %s: %w", seqFile, err)
			}

			var events []*quarry.Event
			if err := json.Unmarshal(data, &events); err != nil {
				return fmt.Errorf("failed to parse sequence events JSON: %w", err)
			}

			// 4. Execute Simulation
			headerStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00D26A"))
			warnStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF8000"))
			critStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF0055"))

			fmt.Println(headerStyle.Render("⚡ Argus Project Quarry: Attack Sequence Simulation"))
			fmt.Printf("   Rules Loaded:    %d from %s\n", len(rules), rulesPath)
			fmt.Printf("   Sequence Events: %d from %s\n", len(events), seqFile)
			fmt.Printf("   Alert Dispatch:  %s\n\n", sock)

			startTime := time.Now()
			var allAlerts []*quarry.Alert

			for idx, ev := range events {
				stepStart := time.Now()
				alerts, err := correlator.Ingest(ev)
				stepLatency := time.Since(stepStart)
				if err != nil {
					return fmt.Errorf("failed to ingest event %d: %w", idx, err)
				}

				layerTag := fmt.Sprintf("[%s]", ev.Layer)
				fmt.Printf("   [%d/%d] %-14s action=%-18s latency=%v\n",
					idx+1, len(events), layerTag, ev.Action, stepLatency)

				if len(alerts) > 0 {
					allAlerts = append(allAlerts, alerts...)
					for _, a := range alerts {
						fmt.Printf("   %s Rule=%s Action=%s TargetPID=%d Steps=%v\n",
							critStyle.Render("🚨 ALERT TRIGGERED:"),
							a.RuleName, a.Action, a.AgentPID, a.SequenceSteps)
					}
				}
			}

			totalDuration := time.Since(startTime)
			fmt.Println()
			if len(allAlerts) > 0 {
				fmt.Println(critStyle.Render(fmt.Sprintf("✔ Simulation finished in %v. %d ALERT(S) TRIGGERED.", totalDuration, len(allAlerts))))
				fmt.Println("   Circuit breaker tripped -> Process freeze signal dispatched.")
				return nil
			}

			fmt.Println(warnStyle.Render("⚠️  Simulation finished with 0 alerts triggered (sequence did not complete a rule)."))
			return nil
		},
	}

	cmd.Flags().StringVar(&testSequenceFile, "sequence", "", "Path to attack sequence JSON fixture")
	cmd.Flags().StringVar(&testRulesPath, "rules", "", "Path to Quarry rules YAML directory or file")
	cmd.Flags().StringVar(&testSocketPath, "socket", "", "Unix socket path for alert dispatch")

	return cmd
}
