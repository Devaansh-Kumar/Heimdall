package syscallfilter

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"sync"

	"github.com/Devaansh-Kumar/Heimdall/pkg/x64"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"
)

const KPROBE_SYSCALL_HOOKPOINT = "x64_sys_call"

func BlockSystemCall(ctx context.Context, wg *sync.WaitGroup, sysCallList []uint32, cgroupID uint64) {
	defer wg.Done()

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs syscallfilterObjects
	if err := loadSyscallfilterObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	// Attach ebpf program to kprobe.
	kp, err := link.Kprobe(KPROBE_SYSCALL_HOOKPOINT, objs.SysCallBlock, nil)
	if err != nil {
		log.Fatal("Attaching to kprobe:", err)
	}
	defer kp.Close()

	// Create filter and put in map
	for _, syscall_nr := range sysCallList {
		key := syscallfilterSyscallFilterKey{
			SyscallNr: syscall_nr,
			CgroupId:  cgroupID,
		}
		err = objs.FilterMap.Put(key, syscallfilterFilterRule{
			Pad: 1,
		})
		if err != nil {
			log.Fatal("unable to update map: ", err)
		} else {
			syscall_name, _ := x64.GetSyscallName(int(syscall_nr))
			log.Printf("Successfully added filter: Syscall=%s (Nr=%d), CgroupID=%d\n", syscall_name, syscall_nr, cgroupID)
		}
	}

	// Create new reader to read from perf buffer
	rd, err := perf.NewReader(objs.SyscallEvents, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}
	defer rd.Close()

	// Outputting process details when system call is blocked
	go readPerfEvents(rd)

	<-ctx.Done()
	log.Println("Shutting down syscall blocker...")
}

func readPerfEvents(rd *perf.Reader) {
	var event syscallfilterProcessInfo
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}

			log.Fatal("error reading from perf", err)
			continue
		}

		if err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing error: %s", err)
			continue
		}

		log.Printf("Killed process trying to access blocked system call. PID: %v, UID: %v, CgroupID: %v, Syscall: %v, Command: %s", event.Pid, event.Uid, event.CgroupId, event.SyscallNr, unix.ByteSliceToString(event.Comm[:]))
	}
}
