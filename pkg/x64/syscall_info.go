package x64

import "fmt"

// GetSyscallNumber returns the syscall number based on the name
func GetSyscallNumber(syscallName string) (int, error) {
	if num, exists := SystemCallNumbers[syscallName]; exists {
		return num, nil
	}
	return -1, fmt.Errorf("unknown syscall: %s", syscallName)
}

// GetSyscallName returns the syscall name based on the number
func GetSyscallName(syscallNumber int) (string, error) {
	if num, exists := SystemCallNames[syscallNumber]; exists {
		return num, nil
	}
	return "", fmt.Errorf("unknown syscall number: %v", syscallNumber)
}
