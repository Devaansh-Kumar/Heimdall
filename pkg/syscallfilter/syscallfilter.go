package syscallfilter

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Devaansh-Kumar/Heimdall/pkg/x64"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

const KPROBE_SYSCALL_HOOKPOINT = "x64_sys_call"

func BlockSystemCall(syscall_nr uint32, cgroupID uint64) {
    // Remove resource limits for kernels <5.11.
    if err := rlimit.RemoveMemlock(); err != nil { 
        log.Fatal("Removing memlock:", err)
    }

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

	log.Println("Waiting for events..")

	// Put filter in map
	err = objs.FilterMap.Put(syscall_nr, syscallfilterFilterRule{
		// Uid: uid,
		// MntNsId: mntNsID,
		CgroupId: cgroupID,
	})
	if err != nil {
		log.Fatal("unable to update map: ", err)
	}

	syscall_name, _ := x64.GetSyscallName(int(syscall_nr))
	log.Printf("Successfully added filter: Syscall=%s (Nr=%d), CgroupID=%d\n", syscall_name, syscall_nr, cgroupID)

	// Create new reader to read from perf buffer
	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}
	defer rd.Close()

	// Outputting process details when system call is blocked
	go readPerfEvents(rd)

	waitForExit(rd)
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

		log.Printf("Killed process. PID: %v, UID: %v, MntID: %v, CgroupID: %v, Syscall: %v, Command: %s", event.Pid, event.Uid, event.MntNsId, event.CgroupId, event.SyscallNr, unix.ByteSliceToString(event.Comm[:]))
	}
}

func waitForExit(rd *perf.Reader) {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	<-stopper
	log.Println("Received signal, exiting program..")

	if err := rd.Close(); err != nil {
		log.Fatalf("closing perf event reader: %s", err)
	}
}