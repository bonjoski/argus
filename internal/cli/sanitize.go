package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"bonjoski/argus/internal/model"
	"bonjoski/argus/internal/sanitizer"
)

func newSanitizeCmd() *cobra.Command {
	var (
		outPath    string
		quarantine bool
	)

	cmd := &cobra.Command{
		Use:   "sanitize <archive-file>",
		Short: "Neutralize lifecycle script execution hooks from package archives",
		Long: `Neutralizes install-time lifecycle execution hooks (preinstall, install, postinstall, etc.)
and malicious binary wrappers from NPM (.tgz), Python (.tar.gz/.whl), and generic archives.`,
		Example: `  argus sanitize package.tgz
  argus sanitize package.tgz --out cleaned-package.tgz
  argus sanitize malicious-pkg.tgz --out safe.tgz --quarantine`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			srcPath := args[0]
			data, err := os.ReadFile(srcPath)
			if err != nil {
				return fmt.Errorf("failed to read archive file %s: %w", srcPath, err)
			}

			// If quarantine requested, store original before modifying
			var qRec *sanitizer.QuarantineRecord
			if quarantine {
				store, err := sanitizer.NewQuarantineStore("")
				if err != nil {
					return fmt.Errorf("failed to open quarantine store: %w", err)
				}

				baseName := filepath.Base(srcPath)
				eco := model.EcosystemNPM
				if strings.HasSuffix(baseName, ".whl") || strings.Contains(baseName, "python") {
					eco = model.EcosystemPyPI
				}

				qRec, err = store.Quarantine(eco, baseName, "manual", data, nil, srcPath)
				if err != nil {
					return fmt.Errorf("quarantine failed: %w", err)
				}
			}

			res, err := sanitizer.NeutralizeBytes(data, srcPath)
			if err != nil {
				return fmt.Errorf("neutralization failed: %w", err)
			}

			targetOut := outPath
			if targetOut == "" {
				ext := filepath.Ext(srcPath)
				if strings.HasSuffix(strings.ToLower(srcPath), ".tar.gz") {
					ext = ".tar.gz"
				}
				base := strings.TrimSuffix(srcPath, ext)
				targetOut = base + ".clean" + ext
			}

			if err := os.WriteFile(targetOut, res.Data, 0644); err != nil {
				return fmt.Errorf("failed to write sanitized archive to %s: %w", targetOut, err)
			}

			if jsonOutput {
				type sanitizeJSONOutput struct {
					SourceArchive    string                      `json:"source_archive"`
					CleanArchive     string                      `json:"clean_archive"`
					StrippedHooks    []sanitizer.StrippedHook    `json:"stripped_hooks"`
					RemovedFiles     []string                    `json:"removed_files"`
					NeutralizedFiles []string                    `json:"neutralized_files"`
					OriginalSize     int64                       `json:"original_size"`
					NeutralizedSize  int64                       `json:"neutralized_size"`
					OriginalSHA256   string                      `json:"original_sha256"`
					CleanSHA256      string                      `json:"clean_sha256"`
					Quarantined      *sanitizer.QuarantineRecord `json:"quarantined,omitempty"`
				}

				outObj := sanitizeJSONOutput{
					SourceArchive:    srcPath,
					CleanArchive:     targetOut,
					StrippedHooks:    res.StrippedHooks,
					RemovedFiles:     res.RemovedFiles,
					NeutralizedFiles: res.NeutralizedFiles,
					OriginalSize:     res.OriginalSize,
					NeutralizedSize:  res.NeutralizedSize,
					OriginalSHA256:   res.OriginalSHA256,
					CleanSHA256:      res.CleanSHA256,
					Quarantined:      qRec,
				}
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(outObj)
			}

			fmt.Printf("🛡️ Neutralized Archive Created: %s\n", targetOut)
			fmt.Printf("   Original Size:    %d bytes (SHA256: %s)\n", res.OriginalSize, res.OriginalSHA256)
			fmt.Printf("   Clean Size:       %d bytes (SHA256: %s)\n", res.NeutralizedSize, res.CleanSHA256)
			if len(res.StrippedHooks) > 0 {
				fmt.Println("\n   Stripped Lifecycle Script Hooks:")
				for _, h := range res.StrippedHooks {
					fmt.Printf("   - [%s] %s: %s\n", h.File, h.Hook, h.Command)
				}
			}
			if len(res.RemovedFiles) > 0 {
				fmt.Println("\n   Removed Suspicious Binaries:")
				for _, f := range res.RemovedFiles {
					fmt.Printf("   - %s\n", f)
				}
			}
			if len(res.NeutralizedFiles) > 0 {
				fmt.Println("\n   Neutralized Script Files:")
				for _, f := range res.NeutralizedFiles {
					fmt.Printf("   - %s\n", f)
				}
			}
			if qRec != nil {
				fmt.Printf("\n☣️ Safely Quarantined: %s (ID: %s)\n", qRec.TarballPath, qRec.ID)
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&outPath, "out", "o", "", "Destination path for cleaned archive")
	cmd.Flags().BoolVarP(&quarantine, "quarantine", "q", false, "Store original unvetted archive in Argus Quarantine Store")

	return cmd
}
