package cmd

import (
	"fmt"
	"log"
	"os"

	"github.com/Devaansh-Kumar/Heimdall/pkg/cgroup"
	"github.com/Devaansh-Kumar/Heimdall/pkg/syscallfilter"
	"github.com/Devaansh-Kumar/Heimdall/pkg/x64"
	"github.com/spf13/cobra"
)

const wildcard uint32 = 4294967295

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "syscall_blocker SYSTEM_CALL_NAME",
	Short: "A CLI to block system calls using eBPF",
	Long:  `CLI to add syscall blocking rules dynamically via eBPF.
System calls can be blocked based on different filters like
uid, mount namespace id and container id.
	`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		syscallName := args[0]

		// Get UID and MntNsID from flags
		// uid, _ := cmd.Flags().GetUint32("uid")
		// mntNsID, _ := cmd.Flags().GetUint32("mnt-ns-id")
		containerID, _ := cmd.Flags().GetString("container-id")

		// Convert syscall name to number
		syscallNum, err := x64.GetSyscallNumber(syscallName)
		if err != nil {
			log.Fatalf("Failed to get syscall number: %w", err)
		}

		var cgroupID uint64
		if containerID == "" {
			cgroupID = 0
		} else {
			cgroupID, err = cgroup.GetCgroupID(containerID)
		}

		// Add filter to the eBPF map
		syscallfilter.BlockSystemCall(uint32(syscallNum), cgroupID)
	},
}

// Execute runs the root command
func Execute() {
	// rootCmd.Flags().Uint32P("uid", "u", wildcard, "User ID (optional)")
	// rootCmd.Flags().Uint32P("mnt-ns-id", "m", wildcard, "Mount namespace ID (optional)")
	rootCmd.Flags().StringP("container-id", "c", "", "Long Container ID (optional)")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
