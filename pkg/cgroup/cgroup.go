package cgroup

import (
	"fmt"
	"log"
	"os"
	_ "path"
	"syscall"
)

// GetCgroupID takes container id as input and returns the cgroup id
// This is based on cgroupv2. It can be extended later of cgroupv1 as well
func GetCgroupID(containerID string) (uint64, error) {
	cgroupPath := fmt.Sprintf("/sys/fs/cgroup/system.slice/docker-%s.scope", containerID)
	file, err := os.Stat(cgroupPath)
	if err != nil {
		log.Fatalf("error getting file info for %s: %s", cgroupPath, err)
	}

	stat, ok:= file.Sys().(*syscall.Stat_t)
	if !ok {
		log.Fatalf("failed to get inode number for %s", cgroupPath)
	}

	return stat.Ino, nil
}