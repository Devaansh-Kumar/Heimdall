package main

import (
	"github.com/Devaansh-Kumar/Heimdall/cmd"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target=amd64 -tags=linux -output-dir=pkg/syscallfilter -go-package=syscallfilter syscallfilter src/sys_call.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target=amd64 -tags=linux -output-dir=pkg/privilege -go-package=privilege privilege src/privilege_escalation.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target=amd64 -tags=linux -output-dir=pkg/fileaccess -go-package=fileaccess fileaccess src/file_access.bpf.c


func main() {
	cmd.Execute()
}