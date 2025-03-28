package x64

const (
	SYS_READ                    = 0
	SYS_WRITE                   = 1
	SYS_OPEN                    = 2
	SYS_CLOSE                   = 3
	SYS_STAT                    = 4
	SYS_FSTAT                   = 5
	SYS_LSTAT                   = 6
	SYS_POLL                    = 7
	SYS_LSEEK                   = 8
	SYS_MMAP                    = 9
	SYS_MPROTECT                = 10
	SYS_MUNMAP                  = 11
	SYS_BRK                     = 12
	SYS_RT_SIGACTION            = 13
	SYS_RT_SIGPROCMASK          = 14
	SYS_RT_SIGRETURN            = 15
	SYS_IOCTL                   = 16
	SYS_PREAD64                 = 17
	SYS_PWRITE64                = 18
	SYS_READV                   = 19
	SYS_WRITEV                  = 20
	SYS_ACCESS                  = 21
	SYS_PIPE                    = 22
	SYS_SELECT                  = 23
	SYS_SCHED_YIELD             = 24
	SYS_MREMAP                  = 25
	SYS_MSYNC                   = 26
	SYS_MINCORE                 = 27
	SYS_MADVISE                 = 28
	SYS_SHMGET                  = 29
	SYS_SHMAT                   = 30
	SYS_SHMCTL                  = 31
	SYS_DUP                     = 32
	SYS_DUP2                    = 33
	SYS_PAUSE                   = 34
	SYS_NANOSLEEP               = 35
	SYS_GETITIMER               = 36
	SYS_ALARM                   = 37
	SYS_SETITIMER               = 38
	SYS_GETPID                  = 39
	SYS_SENDFILE                = 40
	SYS_SOCKET                  = 41
	SYS_CONNECT                 = 42
	SYS_ACCEPT                  = 43
	SYS_SENDTO                  = 44
	SYS_RECVFROM                = 45
	SYS_SENDMSG                 = 46
	SYS_RECVMSG                 = 47
	SYS_SHUTDOWN                = 48
	SYS_BIND                    = 49
	SYS_LISTEN                  = 50
	SYS_GETSOCKNAME             = 51
	SYS_GETPEERNAME             = 52
	SYS_SOCKETPAIR              = 53
	SYS_SETSOCKOPT              = 54
	SYS_GETSOCKOPT              = 55
	SYS_CLONE                   = 56
	SYS_FORK                    = 57
	SYS_VFORK                   = 58
	SYS_EXECVE                  = 59
	SYS_EXIT                    = 60
	SYS_WAIT4                   = 61
	SYS_KILL                    = 62
	SYS_UNAME                   = 63
	SYS_SEMGET                  = 64
	SYS_SEMOP                   = 65
	SYS_SEMCTL                  = 66
	SYS_SHMDT                   = 67
	SYS_MSGGET                  = 68
	SYS_MSGSND                  = 69
	SYS_MSGRCV                  = 70
	SYS_MSGCTL                  = 71
	SYS_FCNTL                   = 72
	SYS_FLOCK                   = 73
	SYS_FSYNC                   = 74
	SYS_FDATASYNC               = 75
	SYS_TRUNCATE                = 76
	SYS_FTRUNCATE               = 77
	SYS_GETDENTS                = 78
	SYS_GETCWD                  = 79
	SYS_CHDIR                   = 80
	SYS_FCHDIR                  = 81
	SYS_RENAME                  = 82
	SYS_MKDIR                   = 83
	SYS_RMDIR                   = 84
	SYS_CREAT                   = 85
	SYS_LINK                    = 86
	SYS_UNLINK                  = 87
	SYS_SYMLINK                 = 88
	SYS_READLINK                = 89
	SYS_CHMOD                   = 90
	SYS_FCHMOD                  = 91
	SYS_CHOWN                   = 92
	SYS_FCHOWN                  = 93
	SYS_LCHOWN                  = 94
	SYS_UMASK                   = 95
	SYS_GETTIMEOFDAY            = 96
	SYS_GETRLIMIT               = 97
	SYS_GETRUSAGE               = 98
	SYS_SYSINFO                 = 99
	SYS_TIMES                   = 100
	SYS_PTRACE                  = 101
	SYS_GETUID                  = 102
	SYS_SYSLOG                  = 103
	SYS_GETGID                  = 104
	SYS_SETUID                  = 105
	SYS_SETGID                  = 106
	SYS_GETEUID                 = 107
	SYS_GETEGID                 = 108
	SYS_SETPGID                 = 109
	SYS_GETPPID                 = 110
	SYS_GETPGRP                 = 111
	SYS_SETSID                  = 112
	SYS_SETREUID                = 113
	SYS_SETREGID                = 114
	SYS_GETGROUPS               = 115
	SYS_SETGROUPS               = 116
	SYS_SETRESUID               = 117
	SYS_GETRESUID               = 118
	SYS_SETRESGID               = 119
	SYS_GETRESGID               = 120
	SYS_GETPGID                 = 121
	SYS_SETFSUID                = 122
	SYS_SETFSGID                = 123
	SYS_GETSID                  = 124
	SYS_CAPGET                  = 125
	SYS_CAPSET                  = 126
	SYS_RT_SIGPENDING           = 127
	SYS_RT_SIGTIMEDWAIT         = 128
	SYS_RT_SIGQUEUEINFO         = 129
	SYS_RT_SIGSUSPEND           = 130
	SYS_SIGALTSTACK             = 131
	SYS_UTIME                   = 132
	SYS_MKNOD                   = 133
	SYS_USELIB                  = 134
	SYS_PERSONALITY             = 135
	SYS_USTAT                   = 136
	SYS_STATFS                  = 137
	SYS_FSTATFS                 = 138
	SYS_SYSFS                   = 139
	SYS_GETPRIORITY             = 140
	SYS_SETPRIORITY             = 141
	SYS_SCHED_SETPARAM          = 142
	SYS_SCHED_GETPARAM          = 143
	SYS_SCHED_SETSCHEDULER      = 144
	SYS_SCHED_GETSCHEDULER      = 145
	SYS_SCHED_GET_PRIORITY_MAX  = 146
	SYS_SCHED_GET_PRIORITY_MIN  = 147
	SYS_SCHED_RR_GET_INTERVAL   = 148
	SYS_MLOCK                   = 149
	SYS_MUNLOCK                 = 150
	SYS_MLOCKALL                = 151
	SYS_MUNLOCKALL              = 152
	SYS_VHANGUP                 = 153
	SYS_MODIFY_LDT              = 154
	SYS_PIVOT_ROOT              = 155
	SYS__SYSCTL                 = 156
	SYS_PRCTL                   = 157
	SYS_ARCH_PRCTL              = 158
	SYS_ADJTIMEX                = 159
	SYS_SETRLIMIT               = 160
	SYS_CHROOT                  = 161
	SYS_SYNC                    = 162
	SYS_ACCT                    = 163
	SYS_SETTIMEOFDAY            = 164
	SYS_MOUNT                   = 165
	SYS_UMOUNT2                 = 166
	SYS_SWAPON                  = 167
	SYS_SWAPOFF                 = 168
	SYS_REBOOT                  = 169
	SYS_SETHOSTNAME             = 170
	SYS_SETDOMAINNAME           = 171
	SYS_IOPL                    = 172
	SYS_IOPERM                  = 173
	SYS_CREATE_MODULE           = 174
	SYS_INIT_MODULE             = 175
	SYS_DELETE_MODULE           = 176
	SYS_GET_KERNEL_SYMS         = 177
	SYS_QUERY_MODULE            = 178
	SYS_QUOTACTL                = 179
	SYS_NFSSERVCTL              = 180
	SYS_GETPMSG                 = 181
	SYS_PUTPMSG                 = 182
	SYS_AFS_SYSCALL             = 183
	SYS_TUXCALL                 = 184
	SYS_SECURITY                = 185
	SYS_GETTID                  = 186
	SYS_READAHEAD               = 187
	SYS_SETXATTR                = 188
	SYS_LSETXATTR               = 189
	SYS_FSETXATTR               = 190
	SYS_GETXATTR                = 191
	SYS_LGETXATTR               = 192
	SYS_FGETXATTR               = 193
	SYS_LISTXATTR               = 194
	SYS_LLISTXATTR              = 195
	SYS_FLISTXATTR              = 196
	SYS_REMOVEXATTR             = 197
	SYS_LREMOVEXATTR            = 198
	SYS_FREMOVEXATTR            = 199
	SYS_TKILL                   = 200
	SYS_TIME                    = 201
	SYS_FUTEX                   = 202
	SYS_SCHED_SETAFFINITY       = 203
	SYS_SCHED_GETAFFINITY       = 204
	SYS_SET_THREAD_AREA         = 205
	SYS_IO_SETUP                = 206
	SYS_IO_DESTROY              = 207
	SYS_IO_GETEVENTS            = 208
	SYS_IO_SUBMIT               = 209
	SYS_IO_CANCEL               = 210
	SYS_GET_THREAD_AREA         = 211
	SYS_LOOKUP_DCOOKIE          = 212
	SYS_EPOLL_CREATE            = 213
	SYS_EPOLL_CTL_OLD           = 214
	SYS_EPOLL_WAIT_OLD          = 215
	SYS_REMAP_FILE_PAGES        = 216
	SYS_GETDENTS64              = 217
	SYS_SET_TID_ADDRESS         = 218
	SYS_RESTART_SYSCALL         = 219
	SYS_SEMTIMEDOP              = 220
	SYS_FADVISE64               = 221
	SYS_TIMER_CREATE            = 222
	SYS_TIMER_SETTIME           = 223
	SYS_TIMER_GETTIME           = 224
	SYS_TIMER_GETOVERRUN        = 225
	SYS_TIMER_DELETE            = 226
	SYS_CLOCK_SETTIME           = 227
	SYS_CLOCK_GETTIME           = 228
	SYS_CLOCK_GETRES            = 229
	SYS_CLOCK_NANOSLEEP         = 230
	SYS_EXIT_GROUP              = 231
	SYS_EPOLL_WAIT              = 232
	SYS_EPOLL_CTL               = 233
	SYS_TGKILL                  = 234
	SYS_UTIMES                  = 235
	SYS_VSERVER                 = 236
	SYS_MBIND                   = 237
	SYS_SET_MEMPOLICY           = 238
	SYS_GET_MEMPOLICY           = 239
	SYS_MQ_OPEN                 = 240
	SYS_MQ_UNLINK               = 241
	SYS_MQ_TIMEDSEND            = 242
	SYS_MQ_TIMEDRECEIVE         = 243
	SYS_MQ_NOTIFY               = 244
	SYS_MQ_GETSETATTR           = 245
	SYS_KEXEC_LOAD              = 246
	SYS_WAITID                  = 247
	SYS_ADD_KEY                 = 248
	SYS_REQUEST_KEY             = 249
	SYS_KEYCTL                  = 250
	SYS_IOPRIO_SET              = 251
	SYS_IOPRIO_GET              = 252
	SYS_INOTIFY_INIT            = 253
	SYS_INOTIFY_ADD_WATCH       = 254
	SYS_INOTIFY_RM_WATCH        = 255
	SYS_MIGRATE_PAGES           = 256
	SYS_OPENAT                  = 257
	SYS_MKDIRAT                 = 258
	SYS_MKNODAT                 = 259
	SYS_FCHOWNAT                = 260
	SYS_FUTIMESAT               = 261
	SYS_NEWFSTATAT              = 262
	SYS_UNLINKAT                = 263
	SYS_RENAMEAT                = 264
	SYS_LINKAT                  = 265
	SYS_SYMLINKAT               = 266
	SYS_READLINKAT              = 267
	SYS_FCHMODAT                = 268
	SYS_FACCESSAT               = 269
	SYS_PSELECT6                = 270
	SYS_PPOLL                   = 271
	SYS_UNSHARE                 = 272
	SYS_SET_ROBUST_LIST         = 273
	SYS_GET_ROBUST_LIST         = 274
	SYS_SPLICE                  = 275
	SYS_TEE                     = 276
	SYS_SYNC_FILE_RANGE         = 277
	SYS_VMSPLICE                = 278
	SYS_MOVE_PAGES              = 279
	SYS_UTIMENSAT               = 280
	SYS_EPOLL_PWAIT             = 281
	SYS_SIGNALFD                = 282
	SYS_TIMERFD_CREATE          = 283
	SYS_EVENTFD                 = 284
	SYS_FALLOCATE               = 285
	SYS_TIMERFD_SETTIME         = 286
	SYS_TIMERFD_GETTIME         = 287
	SYS_ACCEPT4                 = 288
	SYS_SIGNALFD4               = 289
	SYS_EVENTFD2                = 290
	SYS_EPOLL_CREATE1           = 291
	SYS_DUP3                    = 292
	SYS_PIPE2                   = 293
	SYS_INOTIFY_INIT1           = 294
	SYS_PREADV                  = 295
	SYS_PWRITEV                 = 296
	SYS_RT_TGSIGQUEUEINFO       = 297
	SYS_PERF_EVENT_OPEN         = 298
	SYS_RECVMMSG                = 299
	SYS_FANOTIFY_INIT           = 300
	SYS_FANOTIFY_MARK           = 301
	SYS_PRLIMIT64               = 302
	SYS_NAME_TO_HANDLE_AT       = 303
	SYS_OPEN_BY_HANDLE_AT       = 304
	SYS_CLOCK_ADJTIME           = 305
	SYS_SYNCFS                  = 306
	SYS_SENDMMSG                = 307
	SYS_SETNS                   = 308
	SYS_GETCPU                  = 309
	SYS_PROCESS_VM_READV        = 310
	SYS_PROCESS_VM_WRITEV       = 311
	SYS_KCMP                    = 312
	SYS_FINIT_MODULE            = 313
	SYS_SCHED_SETATTR           = 314
	SYS_SCHED_GETATTR           = 315
	SYS_RENAMEAT2               = 316
	SYS_SECCOMP                 = 317
	SYS_GETRANDOM               = 318
	SYS_MEMFD_CREATE            = 319
	SYS_KEXEC_FILE_LOAD         = 320
	SYS_BPF                     = 321
	SYS_EXECVEAT                = 322
	SYS_USERFAULTFD             = 323
	SYS_MEMBARRIER              = 324
	SYS_MLOCK2                  = 325
	SYS_COPY_FILE_RANGE         = 326
	SYS_PREADV2                 = 327
	SYS_PWRITEV2                = 328
	SYS_PKEY_MPROTECT           = 329
	SYS_PKEY_ALLOC              = 330
	SYS_PKEY_FREE               = 331
	SYS_STATX                   = 332
	SYS_IO_PGETEVENTS           = 333
	SYS_RSEQ                    = 334
	SYS_PIDFD_SEND_SIGNAL       = 424
	SYS_IO_URING_SETUP          = 425
	SYS_IO_URING_ENTER          = 426
	SYS_IO_URING_REGISTER       = 427
	SYS_OPEN_TREE               = 428
	SYS_MOVE_MOUNT              = 429
	SYS_FSOPEN                  = 430
	SYS_FSCONFIG                = 431
	SYS_FSMOUNT                 = 432
	SYS_FSPICK                  = 433
	SYS_PIDFD_OPEN              = 434
	SYS_CLONE3                  = 435
	SYS_CLOSE_RANGE             = 436
	SYS_OPENAT2                 = 437
	SYS_PIDFD_GETFD             = 438
	SYS_FACCESSAT2              = 439
	SYS_PROCESS_MADVISE         = 440
	SYS_EPOLL_PWAIT2            = 441
	SYS_MOUNT_SETATTR           = 442
	SYS_QUOTACTL_FD             = 443
	SYS_LANDLOCK_CREATE_RULESET = 444
	SYS_LANDLOCK_ADD_RULE       = 445
	SYS_LANDLOCK_RESTRICT_SELF  = 446
	SYS_MEMFD_SECRET            = 447
	SYS_PROCESS_MRELEASE        = 448
	SYS_FUTEX_WAITV             = 449
	SYS_SET_MEMPOLICY_HOME_NODE = 450
	SYS_CACHESTAT               = 451
	SYS_FCHMODAT2               = 452
	SYS_MAP_SHADOW_STACK        = 453
	SYS_FUTEX_WAKE              = 454
	SYS_FUTEX_WAIT              = 455
	SYS_FUTEX_REQUEUE           = 456
	SYS_STATMOUNT               = 457
	SYS_LISTMOUNT               = 458
	SYS_LSM_GET_SELF_ATTR       = 459
	SYS_LSM_SET_SELF_ATTR       = 460
	SYS_LSM_LIST_MODULES        = 461
	SYS_MSEAL                   = 462
)

var SystemCallNames = map[int]string{
	SYS_READ:                    "read",
	SYS_WRITE:                   "write",
	SYS_OPEN:                    "open",
	SYS_CLOSE:                   "close",
	SYS_STAT:                    "stat",
	SYS_FSTAT:                   "fstat",
	SYS_LSTAT:                   "lstat",
	SYS_POLL:                    "poll",
	SYS_LSEEK:                   "lseek",
	SYS_MMAP:                    "mmap",
	SYS_MPROTECT:                "mprotect",
	SYS_MUNMAP:                  "munmap",
	SYS_BRK:                     "brk",
	SYS_RT_SIGACTION:            "rt_sigaction",
	SYS_RT_SIGPROCMASK:          "rt_sigprocmask",
	SYS_RT_SIGRETURN:            "rt_sigreturn",
	SYS_IOCTL:                   "ioctl",
	SYS_PREAD64:                 "pread64",
	SYS_PWRITE64:                "pwrite64",
	SYS_READV:                   "readv",
	SYS_WRITEV:                  "writev",
	SYS_ACCESS:                  "access",
	SYS_PIPE:                    "pipe",
	SYS_SELECT:                  "select",
	SYS_SCHED_YIELD:             "sched_yield",
	SYS_MREMAP:                  "mremap",
	SYS_MSYNC:                   "msync",
	SYS_MINCORE:                 "mincore",
	SYS_MADVISE:                 "madvise",
	SYS_SHMGET:                  "shmget",
	SYS_SHMAT:                   "shmat",
	SYS_SHMCTL:                  "shmctl",
	SYS_DUP:                     "dup",
	SYS_DUP2:                    "dup2",
	SYS_PAUSE:                   "pause",
	SYS_NANOSLEEP:               "nanosleep",
	SYS_GETITIMER:               "getitimer",
	SYS_ALARM:                   "alarm",
	SYS_SETITIMER:               "setitimer",
	SYS_GETPID:                  "getpid",
	SYS_SENDFILE:                "sendfile",
	SYS_SOCKET:                  "socket",
	SYS_CONNECT:                 "connect",
	SYS_ACCEPT:                  "accept",
	SYS_SENDTO:                  "sendto",
	SYS_RECVFROM:                "recvfrom",
	SYS_SENDMSG:                 "sendmsg",
	SYS_RECVMSG:                 "recvmsg",
	SYS_SHUTDOWN:                "shutdown",
	SYS_BIND:                    "bind",
	SYS_LISTEN:                  "listen",
	SYS_GETSOCKNAME:             "getsockname",
	SYS_GETPEERNAME:             "getpeername",
	SYS_SOCKETPAIR:              "socketpair",
	SYS_SETSOCKOPT:              "setsockopt",
	SYS_GETSOCKOPT:              "getsockopt",
	SYS_CLONE:                   "clone",
	SYS_FORK:                    "fork",
	SYS_VFORK:                   "vfork",
	SYS_EXECVE:                  "execve",
	SYS_EXIT:                    "exit",
	SYS_WAIT4:                   "wait4",
	SYS_KILL:                    "kill",
	SYS_UNAME:                   "uname",
	SYS_SEMGET:                  "semget",
	SYS_SEMOP:                   "semop",
	SYS_SEMCTL:                  "semctl",
	SYS_SHMDT:                   "shmdt",
	SYS_MSGGET:                  "msgget",
	SYS_MSGSND:                  "msgsnd",
	SYS_MSGRCV:                  "msgrcv",
	SYS_MSGCTL:                  "msgctl",
	SYS_FCNTL:                   "fcntl",
	SYS_FLOCK:                   "flock",
	SYS_FSYNC:                   "fsync",
	SYS_FDATASYNC:               "fdatasync",
	SYS_TRUNCATE:                "truncate",
	SYS_FTRUNCATE:               "ftruncate",
	SYS_GETDENTS:                "getdents",
	SYS_GETCWD:                  "getcwd",
	SYS_CHDIR:                   "chdir",
	SYS_FCHDIR:                  "fchdir",
	SYS_RENAME:                  "rename",
	SYS_MKDIR:                   "mkdir",
	SYS_RMDIR:                   "rmdir",
	SYS_CREAT:                   "creat",
	SYS_LINK:                    "link",
	SYS_UNLINK:                  "unlink",
	SYS_SYMLINK:                 "symlink",
	SYS_READLINK:                "readlink",
	SYS_CHMOD:                   "chmod",
	SYS_FCHMOD:                  "fchmod",
	SYS_CHOWN:                   "chown",
	SYS_FCHOWN:                  "fchown",
	SYS_LCHOWN:                  "lchown",
	SYS_UMASK:                   "umask",
	SYS_GETTIMEOFDAY:            "gettimeofday",
	SYS_GETRLIMIT:               "getrlimit",
	SYS_GETRUSAGE:               "getrusage",
	SYS_SYSINFO:                 "sysinfo",
	SYS_TIMES:                   "times",
	SYS_PTRACE:                  "ptrace",
	SYS_GETUID:                  "getuid",
	SYS_SYSLOG:                  "syslog",
	SYS_GETGID:                  "getgid",
	SYS_SETUID:                  "setuid",
	SYS_SETGID:                  "setgid",
	SYS_GETEUID:                 "geteuid",
	SYS_GETEGID:                 "getegid",
	SYS_SETPGID:                 "setpgid",
	SYS_GETPPID:                 "getppid",
	SYS_GETPGRP:                 "getpgrp",
	SYS_SETSID:                  "setsid",
	SYS_SETREUID:                "setreuid",
	SYS_SETREGID:                "setregid",
	SYS_GETGROUPS:               "getgroups",
	SYS_SETGROUPS:               "setgroups",
	SYS_SETRESUID:               "setresuid",
	SYS_GETRESUID:               "getresuid",
	SYS_SETRESGID:               "setresgid",
	SYS_GETRESGID:               "getresgid",
	SYS_GETPGID:                 "getpgid",
	SYS_SETFSUID:                "setfsuid",
	SYS_SETFSGID:                "setfsgid",
	SYS_GETSID:                  "getsid",
	SYS_CAPGET:                  "capget",
	SYS_CAPSET:                  "capset",
	SYS_RT_SIGPENDING:           "rt_sigpending",
	SYS_RT_SIGTIMEDWAIT:         "rt_sigtimedwait",
	SYS_RT_SIGQUEUEINFO:         "rt_sigqueueinfo",
	SYS_RT_SIGSUSPEND:           "rt_sigsuspend",
	SYS_SIGALTSTACK:             "sigaltstack",
	SYS_UTIME:                   "utime",
	SYS_MKNOD:                   "mknod",
	SYS_USELIB:                  "uselib",
	SYS_PERSONALITY:             "personality",
	SYS_USTAT:                   "ustat",
	SYS_STATFS:                  "statfs",
	SYS_FSTATFS:                 "fstatfs",
	SYS_SYSFS:                   "sysfs",
	SYS_GETPRIORITY:             "getpriority",
	SYS_SETPRIORITY:             "setpriority",
	SYS_SCHED_SETPARAM:          "sched_setparam",
	SYS_SCHED_GETPARAM:          "sched_getparam",
	SYS_SCHED_SETSCHEDULER:      "sched_setscheduler",
	SYS_SCHED_GETSCHEDULER:      "sched_getscheduler",
	SYS_SCHED_GET_PRIORITY_MAX:  "sched_get_priority_max",
	SYS_SCHED_GET_PRIORITY_MIN:  "sched_get_priority_min",
	SYS_SCHED_RR_GET_INTERVAL:   "sched_rr_get_interval",
	SYS_MLOCK:                   "mlock",
	SYS_MUNLOCK:                 "munlock",
	SYS_MLOCKALL:                "mlockall",
	SYS_MUNLOCKALL:              "munlockall",
	SYS_VHANGUP:                 "vhangup",
	SYS_MODIFY_LDT:              "modify_ldt",
	SYS_PIVOT_ROOT:              "pivot_root",
	SYS__SYSCTL:                 "_sysctl",
	SYS_PRCTL:                   "prctl",
	SYS_ARCH_PRCTL:              "arch_prctl",
	SYS_ADJTIMEX:                "adjtimex",
	SYS_SETRLIMIT:               "setrlimit",
	SYS_CHROOT:                  "chroot",
	SYS_SYNC:                    "sync",
	SYS_ACCT:                    "acct",
	SYS_SETTIMEOFDAY:            "settimeofday",
	SYS_MOUNT:                   "mount",
	SYS_UMOUNT2:                 "umount2",
	SYS_SWAPON:                  "swapon",
	SYS_SWAPOFF:                 "swapoff",
	SYS_REBOOT:                  "reboot",
	SYS_SETHOSTNAME:             "sethostname",
	SYS_SETDOMAINNAME:           "setdomainname",
	SYS_IOPL:                    "iopl",
	SYS_IOPERM:                  "ioperm",
	SYS_CREATE_MODULE:           "create_module",
	SYS_INIT_MODULE:             "init_module",
	SYS_DELETE_MODULE:           "delete_module",
	SYS_GET_KERNEL_SYMS:         "get_kernel_syms",
	SYS_QUERY_MODULE:            "query_module",
	SYS_QUOTACTL:                "quotactl",
	SYS_NFSSERVCTL:              "nfsservctl",
	SYS_GETPMSG:                 "getpmsg",
	SYS_PUTPMSG:                 "putpmsg",
	SYS_AFS_SYSCALL:             "afs_syscall",
	SYS_TUXCALL:                 "tuxcall",
	SYS_SECURITY:                "security",
	SYS_GETTID:                  "gettid",
	SYS_READAHEAD:               "readahead",
	SYS_SETXATTR:                "setxattr",
	SYS_LSETXATTR:               "lsetxattr",
	SYS_FSETXATTR:               "fsetxattr",
	SYS_GETXATTR:                "getxattr",
	SYS_LGETXATTR:               "lgetxattr",
	SYS_FGETXATTR:               "fgetxattr",
	SYS_LISTXATTR:               "listxattr",
	SYS_LLISTXATTR:              "llistxattr",
	SYS_FLISTXATTR:              "flistxattr",
	SYS_REMOVEXATTR:             "removexattr",
	SYS_LREMOVEXATTR:            "lremovexattr",
	SYS_FREMOVEXATTR:            "fremovexattr",
	SYS_TKILL:                   "tkill",
	SYS_TIME:                    "time",
	SYS_FUTEX:                   "futex",
	SYS_SCHED_SETAFFINITY:       "sched_setaffinity",
	SYS_SCHED_GETAFFINITY:       "sched_getaffinity",
	SYS_SET_THREAD_AREA:         "set_thread_area",
	SYS_IO_SETUP:                "io_setup",
	SYS_IO_DESTROY:              "io_destroy",
	SYS_IO_GETEVENTS:            "io_getevents",
	SYS_IO_SUBMIT:               "io_submit",
	SYS_IO_CANCEL:               "io_cancel",
	SYS_GET_THREAD_AREA:         "get_thread_area",
	SYS_LOOKUP_DCOOKIE:          "lookup_dcookie",
	SYS_EPOLL_CREATE:            "epoll_create",
	SYS_EPOLL_CTL_OLD:           "epoll_ctl_old",
	SYS_EPOLL_WAIT_OLD:          "epoll_wait_old",
	SYS_REMAP_FILE_PAGES:        "remap_file_pages",
	SYS_GETDENTS64:              "getdents64",
	SYS_SET_TID_ADDRESS:         "set_tid_address",
	SYS_RESTART_SYSCALL:         "restart_syscall",
	SYS_SEMTIMEDOP:              "semtimedop",
	SYS_FADVISE64:               "fadvise64",
	SYS_TIMER_CREATE:            "timer_create",
	SYS_TIMER_SETTIME:           "timer_settime",
	SYS_TIMER_GETTIME:           "timer_gettime",
	SYS_TIMER_GETOVERRUN:        "timer_getoverrun",
	SYS_TIMER_DELETE:            "timer_delete",
	SYS_CLOCK_SETTIME:           "clock_settime",
	SYS_CLOCK_GETTIME:           "clock_gettime",
	SYS_CLOCK_GETRES:            "clock_getres",
	SYS_CLOCK_NANOSLEEP:         "clock_nanosleep",
	SYS_EXIT_GROUP:              "exit_group",
	SYS_EPOLL_WAIT:              "epoll_wait",
	SYS_EPOLL_CTL:               "epoll_ctl",
	SYS_TGKILL:                  "tgkill",
	SYS_UTIMES:                  "utimes",
	SYS_VSERVER:                 "vserver",
	SYS_MBIND:                   "mbind",
	SYS_SET_MEMPOLICY:           "set_mempolicy",
	SYS_GET_MEMPOLICY:           "get_mempolicy",
	SYS_MQ_OPEN:                 "mq_open",
	SYS_MQ_UNLINK:               "mq_unlink",
	SYS_MQ_TIMEDSEND:            "mq_timedsend",
	SYS_MQ_TIMEDRECEIVE:         "mq_timedreceive",
	SYS_MQ_NOTIFY:               "mq_notify",
	SYS_MQ_GETSETATTR:           "mq_getsetattr",
	SYS_KEXEC_LOAD:              "kexec_load",
	SYS_WAITID:                  "waitid",
	SYS_ADD_KEY:                 "add_key",
	SYS_REQUEST_KEY:             "request_key",
	SYS_KEYCTL:                  "keyctl",
	SYS_IOPRIO_SET:              "ioprio_set",
	SYS_IOPRIO_GET:              "ioprio_get",
	SYS_INOTIFY_INIT:            "inotify_init",
	SYS_INOTIFY_ADD_WATCH:       "inotify_add_watch",
	SYS_INOTIFY_RM_WATCH:        "inotify_rm_watch",
	SYS_MIGRATE_PAGES:           "migrate_pages",
	SYS_OPENAT:                  "openat",
	SYS_MKDIRAT:                 "mkdirat",
	SYS_MKNODAT:                 "mknodat",
	SYS_FCHOWNAT:                "fchownat",
	SYS_FUTIMESAT:               "futimesat",
	SYS_NEWFSTATAT:              "newfstatat",
	SYS_UNLINKAT:                "unlinkat",
	SYS_RENAMEAT:                "renameat",
	SYS_LINKAT:                  "linkat",
	SYS_SYMLINKAT:               "symlinkat",
	SYS_READLINKAT:              "readlinkat",
	SYS_FCHMODAT:                "fchmodat",
	SYS_FACCESSAT:               "faccessat",
	SYS_PSELECT6:                "pselect6",
	SYS_PPOLL:                   "ppoll",
	SYS_UNSHARE:                 "unshare",
	SYS_SET_ROBUST_LIST:         "set_robust_list",
	SYS_GET_ROBUST_LIST:         "get_robust_list",
	SYS_SPLICE:                  "splice",
	SYS_TEE:                     "tee",
	SYS_SYNC_FILE_RANGE:         "sync_file_range",
	SYS_VMSPLICE:                "vmsplice",
	SYS_MOVE_PAGES:              "move_pages",
	SYS_UTIMENSAT:               "utimensat",
	SYS_EPOLL_PWAIT:             "epoll_pwait",
	SYS_SIGNALFD:                "signalfd",
	SYS_TIMERFD_CREATE:          "timerfd_create",
	SYS_EVENTFD:                 "eventfd",
	SYS_FALLOCATE:               "fallocate",
	SYS_TIMERFD_SETTIME:         "timerfd_settime",
	SYS_TIMERFD_GETTIME:         "timerfd_gettime",
	SYS_ACCEPT4:                 "accept4",
	SYS_SIGNALFD4:               "signalfd4",
	SYS_EVENTFD2:                "eventfd2",
	SYS_EPOLL_CREATE1:           "epoll_create1",
	SYS_DUP3:                    "dup3",
	SYS_PIPE2:                   "pipe2",
	SYS_INOTIFY_INIT1:           "inotify_init1",
	SYS_PREADV:                  "preadv",
	SYS_PWRITEV:                 "pwritev",
	SYS_RT_TGSIGQUEUEINFO:       "rt_tgsigqueueinfo",
	SYS_PERF_EVENT_OPEN:         "perf_event_open",
	SYS_RECVMMSG:                "recvmmsg",
	SYS_FANOTIFY_INIT:           "fanotify_init",
	SYS_FANOTIFY_MARK:           "fanotify_mark",
	SYS_PRLIMIT64:               "prlimit64",
	SYS_NAME_TO_HANDLE_AT:       "name_to_handle_at",
	SYS_OPEN_BY_HANDLE_AT:       "open_by_handle_at",
	SYS_CLOCK_ADJTIME:           "clock_adjtime",
	SYS_SYNCFS:                  "syncfs",
	SYS_SENDMMSG:                "sendmmsg",
	SYS_SETNS:                   "setns",
	SYS_GETCPU:                  "getcpu",
	SYS_PROCESS_VM_READV:        "process_vm_readv",
	SYS_PROCESS_VM_WRITEV:       "process_vm_writev",
	SYS_KCMP:                    "kcmp",
	SYS_FINIT_MODULE:            "finit_module",
	SYS_SCHED_SETATTR:           "sched_setattr",
	SYS_SCHED_GETATTR:           "sched_getattr",
	SYS_RENAMEAT2:               "renameat2",
	SYS_SECCOMP:                 "seccomp",
	SYS_GETRANDOM:               "getrandom",
	SYS_MEMFD_CREATE:            "memfd_create",
	SYS_KEXEC_FILE_LOAD:         "kexec_file_load",
	SYS_BPF:                     "bpf",
	SYS_EXECVEAT:                "execveat",
	SYS_USERFAULTFD:             "userfaultfd",
	SYS_MEMBARRIER:              "membarrier",
	SYS_MLOCK2:                  "mlock2",
	SYS_COPY_FILE_RANGE:         "copy_file_range",
	SYS_PREADV2:                 "preadv2",
	SYS_PWRITEV2:                "pwritev2",
	SYS_PKEY_MPROTECT:           "pkey_mprotect",
	SYS_PKEY_ALLOC:              "pkey_alloc",
	SYS_PKEY_FREE:               "pkey_free",
	SYS_STATX:                   "statx",
	SYS_IO_PGETEVENTS:           "io_pgetevents",
	SYS_RSEQ:                    "rseq",
	SYS_PIDFD_SEND_SIGNAL:       "pidfd_send_signal",
	SYS_IO_URING_SETUP:          "io_uring_setup",
	SYS_IO_URING_ENTER:          "io_uring_enter",
	SYS_IO_URING_REGISTER:       "io_uring_register",
	SYS_OPEN_TREE:               "open_tree",
	SYS_MOVE_MOUNT:              "move_mount",
	SYS_FSOPEN:                  "fsopen",
	SYS_FSCONFIG:                "fsconfig",
	SYS_FSMOUNT:                 "fsmount",
	SYS_FSPICK:                  "fspick",
	SYS_PIDFD_OPEN:              "pidfd_open",
	SYS_CLONE3:                  "clone3",
	SYS_CLOSE_RANGE:             "close_range",
	SYS_OPENAT2:                 "openat2",
	SYS_PIDFD_GETFD:             "pidfd_getfd",
	SYS_FACCESSAT2:              "faccessat2",
	SYS_PROCESS_MADVISE:         "process_madvise",
	SYS_EPOLL_PWAIT2:            "epoll_pwait2",
	SYS_MOUNT_SETATTR:           "mount_setattr",
	SYS_QUOTACTL_FD:             "quotactl_fd",
	SYS_LANDLOCK_CREATE_RULESET: "landlock_create_ruleset",
	SYS_LANDLOCK_ADD_RULE:       "landlock_add_rule",
	SYS_LANDLOCK_RESTRICT_SELF:  "landlock_restrict_self",
	SYS_MEMFD_SECRET:            "memfd_secret",
	SYS_PROCESS_MRELEASE:        "process_mrelease",
	SYS_FUTEX_WAITV:             "futex_waitv",
	SYS_SET_MEMPOLICY_HOME_NODE: "set_mempolicy_home_node",
	SYS_CACHESTAT:               "cachestat",
	SYS_FCHMODAT2:               "fchmodat2",
	SYS_MAP_SHADOW_STACK:        "map_shadow_stack",
	SYS_FUTEX_WAKE:              "futex_wake",
	SYS_FUTEX_WAIT:              "futex_wait",
	SYS_FUTEX_REQUEUE:           "futex_requeue",
	SYS_STATMOUNT:               "statmount",
	SYS_LISTMOUNT:               "listmount",
	SYS_LSM_GET_SELF_ATTR:       "lsm_get_self_attr",
	SYS_LSM_SET_SELF_ATTR:       "lsm_set_self_attr",
	SYS_LSM_LIST_MODULES:        "lsm_list_modules",
	SYS_MSEAL:                   "mseal",
}

var SystemCallNumbers = map[string]int{
	"read":                    SYS_READ,
	"write":                   SYS_WRITE,
	"open":                    SYS_OPEN,
	"close":                   SYS_CLOSE,
	"stat":                    SYS_STAT,
	"fstat":                   SYS_FSTAT,
	"lstat":                   SYS_LSTAT,
	"poll":                    SYS_POLL,
	"lseek":                   SYS_LSEEK,
	"mmap":                    SYS_MMAP,
	"mprotect":                SYS_MPROTECT,
	"munmap":                  SYS_MUNMAP,
	"brk":                     SYS_BRK,
	"rt_sigaction":            SYS_RT_SIGACTION,
	"rt_sigprocmask":          SYS_RT_SIGPROCMASK,
	"rt_sigreturn":            SYS_RT_SIGRETURN,
	"ioctl":                   SYS_IOCTL,
	"pread64":                 SYS_PREAD64,
	"pwrite64":                SYS_PWRITE64,
	"readv":                   SYS_READV,
	"writev":                  SYS_WRITEV,
	"access":                  SYS_ACCESS,
	"pipe":                    SYS_PIPE,
	"select":                  SYS_SELECT,
	"sched_yield":             SYS_SCHED_YIELD,
	"mremap":                  SYS_MREMAP,
	"msync":                   SYS_MSYNC,
	"mincore":                 SYS_MINCORE,
	"madvise":                 SYS_MADVISE,
	"shmget":                  SYS_SHMGET,
	"shmat":                   SYS_SHMAT,
	"shmctl":                  SYS_SHMCTL,
	"dup":                     SYS_DUP,
	"dup2":                    SYS_DUP2,
	"pause":                   SYS_PAUSE,
	"nanosleep":               SYS_NANOSLEEP,
	"getitimer":               SYS_GETITIMER,
	"alarm":                   SYS_ALARM,
	"setitimer":               SYS_SETITIMER,
	"getpid":                  SYS_GETPID,
	"sendfile":                SYS_SENDFILE,
	"socket":                  SYS_SOCKET,
	"connect":                 SYS_CONNECT,
	"accept":                  SYS_ACCEPT,
	"sendto":                  SYS_SENDTO,
	"recvfrom":                SYS_RECVFROM,
	"sendmsg":                 SYS_SENDMSG,
	"recvmsg":                 SYS_RECVMSG,
	"shutdown":                SYS_SHUTDOWN,
	"bind":                    SYS_BIND,
	"listen":                  SYS_LISTEN,
	"getsockname":             SYS_GETSOCKNAME,
	"getpeername":             SYS_GETPEERNAME,
	"socketpair":              SYS_SOCKETPAIR,
	"setsockopt":              SYS_SETSOCKOPT,
	"getsockopt":              SYS_GETSOCKOPT,
	"clone":                   SYS_CLONE,
	"fork":                    SYS_FORK,
	"vfork":                   SYS_VFORK,
	"execve":                  SYS_EXECVE,
	"exit":                    SYS_EXIT,
	"wait4":                   SYS_WAIT4,
	"kill":                    SYS_KILL,
	"uname":                   SYS_UNAME,
	"semget":                  SYS_SEMGET,
	"semop":                   SYS_SEMOP,
	"semctl":                  SYS_SEMCTL,
	"shmdt":                   SYS_SHMDT,
	"msgget":                  SYS_MSGGET,
	"msgsnd":                  SYS_MSGSND,
	"msgrcv":                  SYS_MSGRCV,
	"msgctl":                  SYS_MSGCTL,
	"fcntl":                   SYS_FCNTL,
	"flock":                   SYS_FLOCK,
	"fsync":                   SYS_FSYNC,
	"fdatasync":               SYS_FDATASYNC,
	"truncate":                SYS_TRUNCATE,
	"ftruncate":               SYS_FTRUNCATE,
	"getdents":                SYS_GETDENTS,
	"getcwd":                  SYS_GETCWD,
	"chdir":                   SYS_CHDIR,
	"fchdir":                  SYS_FCHDIR,
	"rename":                  SYS_RENAME,
	"mkdir":                   SYS_MKDIR,
	"rmdir":                   SYS_RMDIR,
	"creat":                   SYS_CREAT,
	"link":                    SYS_LINK,
	"unlink":                  SYS_UNLINK,
	"symlink":                 SYS_SYMLINK,
	"readlink":                SYS_READLINK,
	"chmod":                   SYS_CHMOD,
	"fchmod":                  SYS_FCHMOD,
	"chown":                   SYS_CHOWN,
	"fchown":                  SYS_FCHOWN,
	"lchown":                  SYS_LCHOWN,
	"umask":                   SYS_UMASK,
	"gettimeofday":            SYS_GETTIMEOFDAY,
	"getrlimit":               SYS_GETRLIMIT,
	"getrusage":               SYS_GETRUSAGE,
	"sysinfo":                 SYS_SYSINFO,
	"times":                   SYS_TIMES,
	"ptrace":                  SYS_PTRACE,
	"getuid":                  SYS_GETUID,
	"syslog":                  SYS_SYSLOG,
	"getgid":                  SYS_GETGID,
	"setuid":                  SYS_SETUID,
	"setgid":                  SYS_SETGID,
	"geteuid":                 SYS_GETEUID,
	"getegid":                 SYS_GETEGID,
	"setpgid":                 SYS_SETPGID,
	"getppid":                 SYS_GETPPID,
	"getpgrp":                 SYS_GETPGRP,
	"setsid":                  SYS_SETSID,
	"setreuid":                SYS_SETREUID,
	"setregid":                SYS_SETREGID,
	"getgroups":               SYS_GETGROUPS,
	"setgroups":               SYS_SETGROUPS,
	"setresuid":               SYS_SETRESUID,
	"getresuid":               SYS_GETRESUID,
	"setresgid":               SYS_SETRESGID,
	"getresgid":               SYS_GETRESGID,
	"getpgid":                 SYS_GETPGID,
	"setfsuid":                SYS_SETFSUID,
	"setfsgid":                SYS_SETFSGID,
	"getsid":                  SYS_GETSID,
	"capget":                  SYS_CAPGET,
	"capset":                  SYS_CAPSET,
	"rt_sigpending":           SYS_RT_SIGPENDING,
	"rt_sigtimedwait":         SYS_RT_SIGTIMEDWAIT,
	"rt_sigqueueinfo":         SYS_RT_SIGQUEUEINFO,
	"rt_sigsuspend":           SYS_RT_SIGSUSPEND,
	"sigaltstack":             SYS_SIGALTSTACK,
	"utime":                   SYS_UTIME,
	"mknod":                   SYS_MKNOD,
	"uselib":                  SYS_USELIB,
	"personality":             SYS_PERSONALITY,
	"ustat":                   SYS_USTAT,
	"statfs":                  SYS_STATFS,
	"fstatfs":                 SYS_FSTATFS,
	"sysfs":                   SYS_SYSFS,
	"getpriority":             SYS_GETPRIORITY,
	"setpriority":             SYS_SETPRIORITY,
	"sched_setparam":          SYS_SCHED_SETPARAM,
	"sched_getparam":          SYS_SCHED_GETPARAM,
	"sched_setscheduler":      SYS_SCHED_SETSCHEDULER,
	"sched_getscheduler":      SYS_SCHED_GETSCHEDULER,
	"sched_get_priority_max":  SYS_SCHED_GET_PRIORITY_MAX,
	"sched_get_priority_min":  SYS_SCHED_GET_PRIORITY_MIN,
	"sched_rr_get_interval":   SYS_SCHED_RR_GET_INTERVAL,
	"mlock":                   SYS_MLOCK,
	"munlock":                 SYS_MUNLOCK,
	"mlockall":                SYS_MLOCKALL,
	"munlockall":              SYS_MUNLOCKALL,
	"vhangup":                 SYS_VHANGUP,
	"modify_ldt":              SYS_MODIFY_LDT,
	"pivot_root":              SYS_PIVOT_ROOT,
	"_sysctl":                 SYS__SYSCTL,
	"prctl":                   SYS_PRCTL,
	"arch_prctl":              SYS_ARCH_PRCTL,
	"adjtimex":                SYS_ADJTIMEX,
	"setrlimit":               SYS_SETRLIMIT,
	"chroot":                  SYS_CHROOT,
	"sync":                    SYS_SYNC,
	"acct":                    SYS_ACCT,
	"settimeofday":            SYS_SETTIMEOFDAY,
	"mount":                   SYS_MOUNT,
	"umount2":                 SYS_UMOUNT2,
	"swapon":                  SYS_SWAPON,
	"swapoff":                 SYS_SWAPOFF,
	"reboot":                  SYS_REBOOT,
	"sethostname":             SYS_SETHOSTNAME,
	"setdomainname":           SYS_SETDOMAINNAME,
	"iopl":                    SYS_IOPL,
	"ioperm":                  SYS_IOPERM,
	"create_module":           SYS_CREATE_MODULE,
	"init_module":             SYS_INIT_MODULE,
	"delete_module":           SYS_DELETE_MODULE,
	"get_kernel_syms":         SYS_GET_KERNEL_SYMS,
	"query_module":            SYS_QUERY_MODULE,
	"quotactl":                SYS_QUOTACTL,
	"nfsservctl":              SYS_NFSSERVCTL,
	"getpmsg":                 SYS_GETPMSG,
	"putpmsg":                 SYS_PUTPMSG,
	"afs_syscall":             SYS_AFS_SYSCALL,
	"tuxcall":                 SYS_TUXCALL,
	"security":                SYS_SECURITY,
	"gettid":                  SYS_GETTID,
	"readahead":               SYS_READAHEAD,
	"setxattr":                SYS_SETXATTR,
	"lsetxattr":               SYS_LSETXATTR,
	"fsetxattr":               SYS_FSETXATTR,
	"getxattr":                SYS_GETXATTR,
	"lgetxattr":               SYS_LGETXATTR,
	"fgetxattr":               SYS_FGETXATTR,
	"listxattr":               SYS_LISTXATTR,
	"llistxattr":              SYS_LLISTXATTR,
	"flistxattr":              SYS_FLISTXATTR,
	"removexattr":             SYS_REMOVEXATTR,
	"lremovexattr":            SYS_LREMOVEXATTR,
	"fremovexattr":            SYS_FREMOVEXATTR,
	"tkill":                   SYS_TKILL,
	"time":                    SYS_TIME,
	"futex":                   SYS_FUTEX,
	"sched_setaffinity":       SYS_SCHED_SETAFFINITY,
	"sched_getaffinity":       SYS_SCHED_GETAFFINITY,
	"set_thread_area":         SYS_SET_THREAD_AREA,
	"io_setup":                SYS_IO_SETUP,
	"io_destroy":              SYS_IO_DESTROY,
	"io_getevents":            SYS_IO_GETEVENTS,
	"io_submit":               SYS_IO_SUBMIT,
	"io_cancel":               SYS_IO_CANCEL,
	"get_thread_area":         SYS_GET_THREAD_AREA,
	"lookup_dcookie":          SYS_LOOKUP_DCOOKIE,
	"epoll_create":            SYS_EPOLL_CREATE,
	"epoll_ctl_old":           SYS_EPOLL_CTL_OLD,
	"epoll_wait_old":          SYS_EPOLL_WAIT_OLD,
	"remap_file_pages":        SYS_REMAP_FILE_PAGES,
	"getdents64":              SYS_GETDENTS64,
	"set_tid_address":         SYS_SET_TID_ADDRESS,
	"restart_syscall":         SYS_RESTART_SYSCALL,
	"semtimedop":              SYS_SEMTIMEDOP,
	"fadvise64":               SYS_FADVISE64,
	"timer_create":            SYS_TIMER_CREATE,
	"timer_settime":           SYS_TIMER_SETTIME,
	"timer_gettime":           SYS_TIMER_GETTIME,
	"timer_getoverrun":        SYS_TIMER_GETOVERRUN,
	"timer_delete":            SYS_TIMER_DELETE,
	"clock_settime":           SYS_CLOCK_SETTIME,
	"clock_gettime":           SYS_CLOCK_GETTIME,
	"clock_getres":            SYS_CLOCK_GETRES,
	"clock_nanosleep":         SYS_CLOCK_NANOSLEEP,
	"exit_group":              SYS_EXIT_GROUP,
	"epoll_wait":              SYS_EPOLL_WAIT,
	"epoll_ctl":               SYS_EPOLL_CTL,
	"tgkill":                  SYS_TGKILL,
	"utimes":                  SYS_UTIMES,
	"vserver":                 SYS_VSERVER,
	"mbind":                   SYS_MBIND,
	"set_mempolicy":           SYS_SET_MEMPOLICY,
	"get_mempolicy":           SYS_GET_MEMPOLICY,
	"mq_open":                 SYS_MQ_OPEN,
	"mq_unlink":               SYS_MQ_UNLINK,
	"mq_timedsend":            SYS_MQ_TIMEDSEND,
	"mq_timedreceive":         SYS_MQ_TIMEDRECEIVE,
	"mq_notify":               SYS_MQ_NOTIFY,
	"mq_getsetattr":           SYS_MQ_GETSETATTR,
	"kexec_load":              SYS_KEXEC_LOAD,
	"waitid":                  SYS_WAITID,
	"add_key":                 SYS_ADD_KEY,
	"request_key":             SYS_REQUEST_KEY,
	"keyctl":                  SYS_KEYCTL,
	"ioprio_set":              SYS_IOPRIO_SET,
	"ioprio_get":              SYS_IOPRIO_GET,
	"inotify_init":            SYS_INOTIFY_INIT,
	"inotify_add_watch":       SYS_INOTIFY_ADD_WATCH,
	"inotify_rm_watch":        SYS_INOTIFY_RM_WATCH,
	"migrate_pages":           SYS_MIGRATE_PAGES,
	"openat":                  SYS_OPENAT,
	"mkdirat":                 SYS_MKDIRAT,
	"mknodat":                 SYS_MKNODAT,
	"fchownat":                SYS_FCHOWNAT,
	"futimesat":               SYS_FUTIMESAT,
	"newfstatat":              SYS_NEWFSTATAT,
	"unlinkat":                SYS_UNLINKAT,
	"renameat":                SYS_RENAMEAT,
	"linkat":                  SYS_LINKAT,
	"symlinkat":               SYS_SYMLINKAT,
	"readlinkat":              SYS_READLINKAT,
	"fchmodat":                SYS_FCHMODAT,
	"faccessat":               SYS_FACCESSAT,
	"pselect6":                SYS_PSELECT6,
	"ppoll":                   SYS_PPOLL,
	"unshare":                 SYS_UNSHARE,
	"set_robust_list":         SYS_SET_ROBUST_LIST,
	"get_robust_list":         SYS_GET_ROBUST_LIST,
	"splice":                  SYS_SPLICE,
	"tee":                     SYS_TEE,
	"sync_file_range":         SYS_SYNC_FILE_RANGE,
	"vmsplice":                SYS_VMSPLICE,
	"move_pages":              SYS_MOVE_PAGES,
	"utimensat":               SYS_UTIMENSAT,
	"epoll_pwait":             SYS_EPOLL_PWAIT,
	"signalfd":                SYS_SIGNALFD,
	"timerfd_create":          SYS_TIMERFD_CREATE,
	"eventfd":                 SYS_EVENTFD,
	"fallocate":               SYS_FALLOCATE,
	"timerfd_settime":         SYS_TIMERFD_SETTIME,
	"timerfd_gettime":         SYS_TIMERFD_GETTIME,
	"accept4":                 SYS_ACCEPT4,
	"signalfd4":               SYS_SIGNALFD4,
	"eventfd2":                SYS_EVENTFD2,
	"epoll_create1":           SYS_EPOLL_CREATE1,
	"dup3":                    SYS_DUP3,
	"pipe2":                   SYS_PIPE2,
	"inotify_init1":           SYS_INOTIFY_INIT1,
	"preadv":                  SYS_PREADV,
	"pwritev":                 SYS_PWRITEV,
	"rt_tgsigqueueinfo":       SYS_RT_TGSIGQUEUEINFO,
	"perf_event_open":         SYS_PERF_EVENT_OPEN,
	"recvmmsg":                SYS_RECVMMSG,
	"fanotify_init":           SYS_FANOTIFY_INIT,
	"fanotify_mark":           SYS_FANOTIFY_MARK,
	"prlimit64":               SYS_PRLIMIT64,
	"name_to_handle_at":       SYS_NAME_TO_HANDLE_AT,
	"open_by_handle_at":       SYS_OPEN_BY_HANDLE_AT,
	"clock_adjtime":           SYS_CLOCK_ADJTIME,
	"syncfs":                  SYS_SYNCFS,
	"sendmmsg":                SYS_SENDMMSG,
	"setns":                   SYS_SETNS,
	"getcpu":                  SYS_GETCPU,
	"process_vm_readv":        SYS_PROCESS_VM_READV,
	"process_vm_writev":       SYS_PROCESS_VM_WRITEV,
	"kcmp":                    SYS_KCMP,
	"finit_module":            SYS_FINIT_MODULE,
	"sched_setattr":           SYS_SCHED_SETATTR,
	"sched_getattr":           SYS_SCHED_GETATTR,
	"renameat2":               SYS_RENAMEAT2,
	"seccomp":                 SYS_SECCOMP,
	"getrandom":               SYS_GETRANDOM,
	"memfd_create":            SYS_MEMFD_CREATE,
	"kexec_file_load":         SYS_KEXEC_FILE_LOAD,
	"bpf":                     SYS_BPF,
	"execveat":                SYS_EXECVEAT,
	"userfaultfd":             SYS_USERFAULTFD,
	"membarrier":              SYS_MEMBARRIER,
	"mlock2":                  SYS_MLOCK2,
	"copy_file_range":         SYS_COPY_FILE_RANGE,
	"preadv2":                 SYS_PREADV2,
	"pwritev2":                SYS_PWRITEV2,
	"pkey_mprotect":           SYS_PKEY_MPROTECT,
	"pkey_alloc":              SYS_PKEY_ALLOC,
	"pkey_free":               SYS_PKEY_FREE,
	"statx":                   SYS_STATX,
	"io_pgetevents":           SYS_IO_PGETEVENTS,
	"rseq":                    SYS_RSEQ,
	"pidfd_send_signal":       SYS_PIDFD_SEND_SIGNAL,
	"io_uring_setup":          SYS_IO_URING_SETUP,
	"io_uring_enter":          SYS_IO_URING_ENTER,
	"io_uring_register":       SYS_IO_URING_REGISTER,
	"open_tree":               SYS_OPEN_TREE,
	"move_mount":              SYS_MOVE_MOUNT,
	"fsopen":                  SYS_FSOPEN,
	"fsconfig":                SYS_FSCONFIG,
	"fsmount":                 SYS_FSMOUNT,
	"fspick":                  SYS_FSPICK,
	"pidfd_open":              SYS_PIDFD_OPEN,
	"clone3":                  SYS_CLONE3,
	"close_range":             SYS_CLOSE_RANGE,
	"openat2":                 SYS_OPENAT2,
	"pidfd_getfd":             SYS_PIDFD_GETFD,
	"faccessat2":              SYS_FACCESSAT2,
	"process_madvise":         SYS_PROCESS_MADVISE,
	"epoll_pwait2":            SYS_EPOLL_PWAIT2,
	"mount_setattr":           SYS_MOUNT_SETATTR,
	"quotactl_fd":             SYS_QUOTACTL_FD,
	"landlock_create_ruleset": SYS_LANDLOCK_CREATE_RULESET,
	"landlock_add_rule":       SYS_LANDLOCK_ADD_RULE,
	"landlock_restrict_self":  SYS_LANDLOCK_RESTRICT_SELF,
	"memfd_secret":            SYS_MEMFD_SECRET,
	"process_mrelease":        SYS_PROCESS_MRELEASE,
	"futex_waitv":             SYS_FUTEX_WAITV,
	"set_mempolicy_home_node": SYS_SET_MEMPOLICY_HOME_NODE,
	"cachestat":               SYS_CACHESTAT,
	"fchmodat2":               SYS_FCHMODAT2,
	"map_shadow_stack":        SYS_MAP_SHADOW_STACK,
	"futex_wake":              SYS_FUTEX_WAKE,
	"futex_wait":              SYS_FUTEX_WAIT,
	"futex_requeue":           SYS_FUTEX_REQUEUE,
	"statmount":               SYS_STATMOUNT,
	"listmount":               SYS_LISTMOUNT,
	"lsm_get_self_attr":       SYS_LSM_GET_SELF_ATTR,
	"lsm_set_self_attr":       SYS_LSM_SET_SELF_ATTR,
	"lsm_list_modules":        SYS_LSM_LIST_MODULES,
	"mseal":                   SYS_MSEAL,
}
