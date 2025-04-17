package privilege

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"sync"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"
)

const KPROBE_SYSCALL_HOOKPOINT = "x64_sys_call"

func BlockPrivilegeEscalation(ctx context.Context, wg *sync.WaitGroup, cgroupID uint64) {
	defer wg.Done()

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs privilegeObjects
	if err := loadPrivilegeObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	// Attach ebpf program to kprobe.
	lsm, err := link.AttachLSM(link.LSMOptions{
		Program: objs.HandleCredPrepare,
	})
	if err != nil {
		log.Fatal("Attaching to kprobe:", err)
	}
	defer lsm.Close()

	// Create filter and put in map
	key := privilegePrivilegeKey{
		CgroupId: cgroupID,
	}
	err = objs.PrivilegeMap.Put(key, privilegeFilterPad{
		Pad: 1,
	})
	if err != nil {
		log.Fatal("unable to update map: ", err)
	} else {
		log.Printf("Successfully added rule to block privilege escalation attempts")
	}

	// Create new reader to read from perf buffer
	rd, err := perf.NewReader(objs.PrivilegeEscalationEvents, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}
	defer rd.Close()

	// Outputting process details when privilege escalation is detected
	go readPerfEvents(rd)

	<-ctx.Done()
	log.Println("Shutting down privilege escalation blocker...")
}

func readPerfEvents(rd *perf.Reader) {
	var event privilegeProcessInfo
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

		log.Printf("Blocked privilege escalation in container. PID: %v, UID: %v, CgroupID: %v, Syscall: %v, Command: %s", event.Pid, event.Uid, event.CgroupId, event.SyscallNr, unix.ByteSliceToString(event.Comm[:]))
	}
}
