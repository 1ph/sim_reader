package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var completionCmd = &cobra.Command{
	Use:   "completion [bash|zsh|fish|powershell]",
	Short: "Generate shell completion scripts",
	Long: `Generate shell completion scripts for sim_reader.

To load completions:

Bash:
  $ source <(sim_reader completion bash)

  # To load completions for each session, execute once:
  # Linux:
  $ sim_reader completion bash > /etc/bash_completion.d/sim_reader
  # macOS:
  $ sim_reader completion bash > $(brew --prefix)/etc/bash_completion.d/sim_reader

Zsh:
  # If shell completion is not already enabled in your environment,
  # you will need to enable it. You can execute the following once:
  $ echo "autoload -U compinit; compinit" >> ~/.zshrc

  # To load completions for each session, execute once:
  $ sim_reader completion zsh > "${fpath[1]}/_sim_reader"

  # You will need to start a new shell for this setup to take effect.

Fish:
  $ sim_reader completion fish | source

  # To load completions for each session, execute once:
  $ sim_reader completion fish > ~/.config/fish/completions/sim_reader.fish

PowerShell:
  PS> sim_reader completion powershell | Out-String | Invoke-Expression

  # To load completions for every new session, run:
  PS> sim_reader completion powershell > sim_reader.ps1
  # and source this file from your PowerShell profile.
`,
	DisableFlagsInUseLine: true,
	ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
	Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	Run: func(cmd *cobra.Command, args []string) {
		switch args[0] {
		case "bash":
			rootCmd.GenBashCompletion(os.Stdout)
		case "zsh":
			rootCmd.GenZshCompletion(os.Stdout)
		case "fish":
			rootCmd.GenFishCompletion(os.Stdout, true)
		case "powershell":
			rootCmd.GenPowerShellCompletionWithDesc(os.Stdout)
		}
	},
}

func init() {
	rootCmd.AddCommand(completionCmd)
}

