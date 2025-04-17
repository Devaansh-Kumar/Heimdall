package fileaccess

import (
	"log"
	"os"
	"sync"
	"context"
	// "errors"
	// "encoding/binary"
	// "bytes"
	

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	// "golang.org/x/sys/unix"
)

const LSM_BPF_HOOKPOINT = "file_open"

func BlockFileOpen(ctx context.Context, wg *sync.WaitGroup, cgroupID uint64, filePath string) {
	defer wg.Done()


	// Load the compiled eBPF ELF and load it into the kernel.
	var objs fileaccessObjects
	if err := loadFileaccessObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects: ", err)
	}
	defer objs.Close()

	// Attach ebpf program to LSM hookpoint.
	opts := link.LSMOptions{Program: objs.RestrictFileOpen}
	kp, err := link.AttachLSM(opts)
	if err != nil {
		log.Fatal("Opening tracepoint: ", err)
	}
	defer kp.Close()

	// Create filter and put in map
	key := uint32(0)

	var val fileaccessFilePath
	for i := 0; i < len(filePath); i++ {
		val.Path[i] = int8(filePath[i])
	}
	val.CgroupId = cgroupID
	err = objs.BlockedFiles.Put(key, val)
	if err != nil {
		log.Fatal("Could not put in map: ", err)
	} else {
		log.Printf("Added %s to Blocked File Paths", filePath)
	}

	// Create new reader to read from perf buffer
	rd, err := perf.NewReader(objs.FileAccessEvents, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}
	defer rd.Close()

	// Outputting process details when system call is blocked
	// go readPerfEvents(rd)

	<-ctx.Done()
	log.Println("Shutting down  file access blocker...")
}

// func readPerfEvents(rd *perf.Reader) {
// 	var event fileaccessProcessInfo
// 	for {
// 		record, err := rd.Read()
// 		if err != nil {
// 			if errors.Is(err, perf.ErrClosed) {
// 				return
// 			}

// 			log.Fatal("error reading from perf", err)
// 			continue
// 		}

// 		if err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
// 			log.Printf("parsing error: %s", err)
// 			continue
// 		}

// 		log.Printf("Blocked File Path. PID: %v, UID: %v, Command: %s", event.Pid, event.Uid, unix.ByteSliceToString(event.Comm[:]))
// 	}
// }
