package cmd

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/Devaansh-Kumar/Heimdall/pkg/cgroup"
	"github.com/Devaansh-Kumar/Heimdall/pkg/privilege"
	"github.com/Devaansh-Kumar/Heimdall/pkg/syscallfilter"
	"github.com/Devaansh-Kumar/Heimdall/pkg/x64"
	"github.com/Devaansh-Kumar/Heimdall/pkg/fileaccess"
	"github.com/cilium/ebpf/rlimit"
	"github.com/spf13/cobra"
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "syscall_blocker SYSTEM_CALL_NAME",
	Short: "A CLI to block system calls using eBPF for containers",
	Long:  `CLI to add syscall blocking rules via eBPF for containers.`,
	Run: func(cmd *cobra.Command, args []string) {
		containerID, _ := cmd.Flags().GetString("container-id")
		syscalls, _ := cmd.Flags().GetStringSlice("block-syscalls")
		privEscalation, _ := cmd.Flags().GetBool("block-privilege-escalation")
		filePath, _ := cmd.Flags().GetStringSlice("file-path")

		// Get cgroup id from container name
		cgroupID, err := cgroup.GetCgroupID(containerID)
		if err != nil {
			log.Fatalf("Failed to get cgroup ID for container %s: %v", containerID, err)
		}

		var systemCallList []uint32
		for _, syscallName := range syscalls {
			// Convert syscall name to number
			syscallNum, err := x64.GetSyscallNumber(syscallName)
			if err != nil {
				log.Fatalf("Failed to get syscall number: %s", err)
			}
			systemCallList = append(systemCallList, uint32(syscallNum))
		}

		// For synchronizing program loading and unloading on exit
		ctx, cancel := context.WithCancel(context.Background())
		var wg sync.WaitGroup

		// Set up signal handling to cancel context on Ctrl+C or SIGTERM
		go func() {
			sig := make(chan os.Signal, 1)
			signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
			<-sig
			fmt.Println("Received signal, exiting...")
			cancel()
		}()

		started := false

		// Loading syscall blocker only if user provided syscalls
		// and adding to waitgroup
		if len(syscalls) > 0 {
			wg.Add(1)
			go syscallfilter.BlockSystemCall(ctx, &wg, systemCallList, cgroupID)
			started = true
		}

		// Loading privilege escalation blocker if requested
		// and adding to waitgroup
		if privEscalation {
			wg.Add(1)
			go privilege.BlockPrivilegeEscalation(ctx, &wg, cgroupID)
			started = true
		}

		if len(filePath) > 0 {
			wg.Add(1)
			// fmt.Println("Blocking file access for paths:", filePath)
			go fileaccess.BlockFileOpen(ctx, &wg, cgroupID, filePath)
			started = true
		}

		if started {
			<-ctx.Done() // Wait until termination signal is received
			wg.Wait()    // Wait for background tasks to finish
		} else {
			log.Println("No filters applied. Exiting")
		}

	},
}

// Execute runs the root command
func Execute() {
	rootCmd.Flags().StringP("container-id", "c", "", "Long Container ID")
	rootCmd.Flags().StringSliceP("block-syscalls", "s", []string{}, "List of system calls to block")
	rootCmd.Flags().BoolP("block-privilege-escalation", "p", false, "Block Privilege Escalation attempts for the container")
	rootCmd.Flags().StringSliceP("file-path", "f", []string{}, "File path to block")


	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
