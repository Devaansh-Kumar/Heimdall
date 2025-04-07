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

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "syscall_blocker SYSTEM_CALL_NAME",
	Short: "A CLI to block system calls using eBPF for containers",
	Long:  `CLI to add syscall blocking rules via eBPF for containers.`,
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		containerID, _ := cmd.Flags().GetString("container-id")

		// Get cgroup id from container name
		cgroupID, err := cgroup.GetCgroupID(containerID)
		if err != nil {
			log.Fatalf("Failed to get cgroup ID for container %s: %v", containerID, err)
		}

		var systemCallList []uint32
		for _, syscallName := range args {
			// Convert syscall name to number
			syscallNum, err := x64.GetSyscallNumber(syscallName)
			if err != nil {
				log.Fatalf("Failed to get syscall number: %w", err)
			}
			systemCallList = append(systemCallList, uint32(syscallNum))
		}

		// Add filter to the eBPF map
		syscallfilter.BlockSystemCall(systemCallList, cgroupID)
	},
}

// Execute runs the root command
func Execute() {
	rootCmd.Flags().StringP("container-id", "c", "", "Long Container ID")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
