// Package nsjail provides a complete and idiomatic Go wrapper for the NSJail
// process isolation tool. It allows for programmatic configuration and execution
// of sandboxed processes using a fluent builder API.
package nsjail

import (
	"fmt"
	"os/exec"
	"strconv"
)

// Mode defines the execution mode for NSJail.
type Mode string

const (
	// ModeListenTCP waits for connections on a TCP port (--mode l).
	ModeListenTCP Mode = "l"
	// ModeOnce launches a single process on the console using clone/execve (--mode o).
	ModeOnce Mode = "o"
	// ModeExecve launches a single process on the console using execve (--mode e).
	ModeExecve Mode = "e"
	// ModeRerun launches a single process and re-runs it forever (--mode r).
	ModeRerun Mode = "r"
)

// RlimitVal represents a special resource limit value.
type RlimitVal string

const (
	// RlimitMax or RlimitHard uses the current hard limit.
	RlimitMax RlimitVal = "max"
	// RlimitHard or RlimitMax uses the current hard limit.
	RlimitHard RlimitVal = "hard"
	// RlimitDef or RlimitSoft uses the current soft limit.
	RlimitDef RlimitVal = "def"
	// RlimitSoft or RlimitDef uses the current soft limit.
	RlimitSoft RlimitVal = "soft"
	// RlimitInf uses RLIM64_INFINITY.
	RlimitInf RlimitVal = "inf"
)

// MacVlanMode defines the mode for a MACVLAN interface.
type MacVlanMode string

const (
	MacVlanPrivate  MacVlanMode = "private"
	MacVlanVepa     MacVlanMode = "vepa"
	MacVlanBridge   MacVlanMode = "bridge"
	MacVlanPassthru MacVlanMode = "passthru"
)

// Mount represents a custom mount point configuration for the --mount flag.
type Mount struct {
	Src    string
	Dst    string
	FsType string
	Opts   string
}

// Symlink represents a symbolic link to be created in the jail for the --symlink flag.
type Symlink struct {
	Src string
	Dst string
}

// NsJail holds the complete configuration for a single NSJail execution.
// It is configured using the builder methods.
type NsJail struct {
	path    string
	execCmd string
	args    []string

	// Core options
	mode       Mode
	configFile string
	execFile   string
	executeFd  bool

	// Isolation options
	chroot            string
	noPivotRoot       bool
	rwChroot          bool
	user              string
	group             string
	hostname          string
	cwd               string
	keepEnv           bool
	envVars           []string
	keepCaps          bool
	caps              []string
	silent            bool
	stderrToNull      bool
	skipSetsid        bool
	passFds           []int
	disableNoNewPrivs bool

	// Namespaces
	cloneNewNetDisabled    bool
	cloneNewUserDisabled   bool
	cloneNewNsDisabled     bool
	cloneNewPidDisabled    bool
	cloneNewIpcDisabled    bool
	cloneNewUtsDisabled    bool
	cloneNewCgroupDisabled bool
	cloneNewTimeEnabled    bool
	uidMappings            []string
	gidMappings            []string

	// Resource limits
	timeLimit      uint64
	maxCpus        uint
	rlimitAs       string // Supports numbers and RlimitVal
	rlimitCore     string
	rlimitCpu      string
	rlimitFsize    string
	rlimitNofile   string
	rlimitNproc    string
	rlimitStack    string
	rlimitMemlock  string
	rlimitRtprio   string
	rlimitMsgqueue string
	disableRlimits bool

	// Personality
	personaAddrCompatLayout bool
	personaMmapPageZero     bool
	personaReadImpliesExec  bool
	personaAddrLimit3gb     bool
	personaAddrNoRandomize  bool

	// Mounts
	bindMountsRO      []string
	bindMountsRW      []string
	tmpfsMounts       []string
	mounts            []Mount
	symlinks          []Symlink
	procMountDisabled bool
	procPath          string
	procRw            bool

	// Network options
	port          uint16
	bindhost      string
	maxConns      uint
	maxConnsPerIp uint
	ifaceNoLo     bool
	ifaceOwn      []string

	// MACVLAN options
	macvlanIface string
	macvlanVsIp  string
	macvlanVsNm  string
	macvlanVsGw  string
	macvlanVsMa  string
	macvlanVsMo  MacVlanMode

	// Seccomp
	seccompPolicy string
	seccompString string
	seccompLog    bool

	// Cgroups v1
	cgroupMemMax        uint64
	cgroupMemMemswMax   uint64
	cgroupMemSwapMax    string // Can be "-1"
	cgroupMemMount      string
	cgroupMemParent     string
	cgroupPidsMax       uint
	cgroupPidsMount     string
	cgroupPidsParent    string
	cgroupNetClsClassid uint32
	cgroupNetClsMount   string
	cgroupNetClsParent  string
	cgroupCpuMsPerSec   uint
	cgroupCpuMount      string
	cgroupCpuParent     string

	// Cgroups v2
	cgroupv2Mount  string
	useCgroupv2    bool
	detectCgroupv2 bool

	// Other
	logFile        string
	logFd          int
	daemon         bool
	verbose        bool
	quiet          bool
	reallyQuiet    bool
	niceLevel      int
	disableTsc     bool
	forwardSignals bool
}

// New creates a new NsJail configuration for the given command and arguments.
// The path to the nsjail binary defaults to "nsjail" and can be overridden with WithPath().
func New(cmd string, args ...string) *NsJail {
	return &NsJail{
		path:      "nsjail",
		execCmd:   cmd,
		args:      args,
		logFd:     -1,   // Use -1 to indicate not set, nsjail default is 2
		niceLevel: -256, // Use magic number to indicate not set
	}
}

// Exec builds the final exec.Cmd object based on the NsJail configuration.
// This allows the caller to manage stdin/stdout/stderr and how the process is run.
func (n *NsJail) Exec() (*exec.Cmd, error) {
	args := []string{}

	// Helper functions
	appendFlag := func(flag, value string) {
		if value != "" {
			args = append(args, flag, value)
		}
	}
	appendFlagUint := func(flag string, value uint) {
		if value > 0 {
			args = append(args, flag, strconv.FormatUint(uint64(value), 10))
		}
	}
	appendFlagUint64 := func(flag string, value uint64) {
		if value > 0 {
			args = append(args, flag, strconv.FormatUint(value, 10))
		}
	}
	appendFlagBool := func(flag string, value bool) {
		if value {
			args = append(args, flag)
		}
	}
	appendFlagSlice := func(flag string, values []string) {
		for _, v := range values {
			args = append(args, flag, v)
		}
	}

	// Build arguments from configuration
	if n.mode != "" {
		args = append(args, "-M", string(n.mode))
	}
	appendFlag("-C", n.configFile)
	appendFlag("-x", n.execFile)
	appendFlagBool("--execute_fd", n.executeFd)

	appendFlag("-c", n.chroot)
	appendFlagBool("--no_pivotroot", n.noPivotRoot)
	appendFlagBool("--rw", n.rwChroot)
	appendFlag("-u", n.user)
	appendFlag("-g", n.group)
	appendFlag("-H", n.hostname)
	appendFlag("-D", n.cwd)
	appendFlagBool("-e", n.keepEnv)
	appendFlagSlice("-E", n.envVars)
	appendFlagBool("--keep_caps", n.keepCaps)
	appendFlagSlice("--cap", n.caps)
	appendFlagBool("--silent", n.silent)
	appendFlagBool("--stderr_to_null", n.stderrToNull)
	appendFlagBool("--skip_setsid", n.skipSetsid)
	for _, fd := range n.passFds {
		args = append(args, "--pass_fd", strconv.Itoa(fd))
	}
	appendFlagBool("--disable_no_new_privs", n.disableNoNewPrivs)

	appendFlagBool("-N", n.cloneNewNetDisabled)
	appendFlagBool("--disable_clone_newuser", n.cloneNewUserDisabled)
	appendFlagBool("--disable_clone_newns", n.cloneNewNsDisabled)
	appendFlagBool("--disable_clone_newpid", n.cloneNewPidDisabled)
	appendFlagBool("--disable_clone_newipc", n.cloneNewIpcDisabled)
	appendFlagBool("--disable_clone_newuts", n.cloneNewUtsDisabled)
	appendFlagBool("--disable_clone_newcgroup", n.cloneNewCgroupDisabled)
	appendFlagBool("--enable_clone_newtime", n.cloneNewTimeEnabled)
	appendFlagSlice("-U", n.uidMappings)
	appendFlagSlice("-G", n.gidMappings)

	appendFlagUint64("-t", n.timeLimit)
	appendFlagUint("--max_cpus", n.maxCpus)
	appendFlag("--rlimit_as", n.rlimitAs)
	appendFlag("--rlimit_core", n.rlimitCore)
	appendFlag("--rlimit_cpu", n.rlimitCpu)
	appendFlag("--rlimit_fsize", n.rlimitFsize)
	appendFlag("--rlimit_nofile", n.rlimitNofile)
	appendFlag("--rlimit_nproc", n.rlimitNproc)
	appendFlag("--rlimit_stack", n.rlimitStack)
	appendFlag("--rlimit_memlock", n.rlimitMemlock)
	appendFlag("--rlimit_rtprio", n.rlimitRtprio)
	appendFlag("--rlimit_msgqueue", n.rlimitMsgqueue)
	appendFlagBool("--disable_rlimits", n.disableRlimits)

	appendFlagBool("--persona_addr_compat_layout", n.personaAddrCompatLayout)
	appendFlagBool("--persona_mmap_page_zero", n.personaMmapPageZero)
	appendFlagBool("--persona_read_implies_exec", n.personaReadImpliesExec)
	appendFlagBool("--persona_addr_limit_3gb", n.personaAddrLimit3gb)
	appendFlagBool("--persona_addr_no_randomize", n.personaAddrNoRandomize)

	appendFlagSlice("-R", n.bindMountsRO)
	appendFlagSlice("-B", n.bindMountsRW)
	appendFlagSlice("-T", n.tmpfsMounts)
	for _, m := range n.mounts {
		mountStr := fmt.Sprintf("%s:%s:%s:%s", m.Src, m.Dst, m.FsType, m.Opts)
		args = append(args, "-m", mountStr)
	}
	for _, s := range n.symlinks {
		symlinkStr := fmt.Sprintf("%s:%s", s.Src, s.Dst)
		args = append(args, "-s", symlinkStr)
	}
	appendFlagBool("--disable_proc", n.procMountDisabled)
	appendFlag("--proc_path", n.procPath)
	appendFlagBool("--proc_rw", n.procRw)

	if n.port > 0 {
		args = append(args, "-p", strconv.Itoa(int(n.port)))
	}
	appendFlag("--bindhost", n.bindhost)
	appendFlagUint("--max_conns", n.maxConns)
	appendFlagUint("-i", n.maxConnsPerIp)
	appendFlagBool("--iface_no_lo", n.ifaceNoLo)
	appendFlagSlice("--iface_own", n.ifaceOwn)

	appendFlag("-I", n.macvlanIface)
	appendFlag("--macvlan_vs_ip", n.macvlanVsIp)
	appendFlag("--macvlan_vs_nm", n.macvlanVsNm)
	appendFlag("--macvlan_vs_gw", n.macvlanVsGw)
	appendFlag("--macvlan_vs_ma", n.macvlanVsMa)
	if n.macvlanVsMo != "" {
		args = append(args, "--macvlan_vs_mo", string(n.macvlanVsMo))
	}

	appendFlag("-P", n.seccompPolicy)
	appendFlag("--seccomp_string", n.seccompString)
	appendFlagBool("--seccomp_log", n.seccompLog)

	appendFlagUint64("--cgroup_mem_max", n.cgroupMemMax)
	appendFlagUint64("--cgroup_mem_memsw_max", n.cgroupMemMemswMax)
	appendFlag("--cgroup_mem_swap_max", n.cgroupMemSwapMax)
	appendFlag("--cgroup_mem_mount", n.cgroupMemMount)
	appendFlag("--cgroup_mem_parent", n.cgroupMemParent)
	appendFlagUint("--cgroup_pids_max", n.cgroupPidsMax)
	appendFlag("--cgroup_pids_mount", n.cgroupPidsMount)
	appendFlag("--cgroup_pids_parent", n.cgroupPidsParent)
	if n.cgroupNetClsClassid > 0 {
		args = append(args, "--cgroup_net_cls_classid", fmt.Sprintf("0x%x", n.cgroupNetClsClassid))
	}
	appendFlag("--cgroup_net_cls_mount", n.cgroupNetClsMount)
	appendFlag("--cgroup_net_cls_parent", n.cgroupNetClsParent)
	appendFlagUint("--cgroup_cpu_ms_per_sec", n.cgroupCpuMsPerSec)
	appendFlag("--cgroup_cpu_mount", n.cgroupCpuMount)
	appendFlag("--cgroup_cpu_parent", n.cgroupCpuParent)
	appendFlag("--cgroupv2_mount", n.cgroupv2Mount)
	appendFlagBool("--use_cgroupv2", n.useCgroupv2)
	appendFlagBool("--detect_cgroupv2", n.detectCgroupv2)

	appendFlag("-l", n.logFile)
	if n.logFd != -1 {
		args = append(args, "-L", strconv.Itoa(n.logFd))
	}
	appendFlagBool("-d", n.daemon)
	appendFlagBool("-v", n.verbose)
	appendFlagBool("-q", n.quiet)
	appendFlagBool("-Q", n.reallyQuiet)
	if n.niceLevel != -256 {
		args = append(args, "--nice_level", strconv.Itoa(n.niceLevel))
	}
	appendFlagBool("--disable_tsc", n.disableTsc)
	appendFlagBool("--forward_signals", n.forwardSignals)

	// Command and its arguments
	if n.execCmd != "" {
		args = append(args, "--", n.execCmd)
		args = append(args, n.args...)
	}

	cmd := exec.Command(n.path, args...)
	return cmd, nil
}

// String returns the string representation of the command to be executed. Useful for debugging.
func (n *NsJail) String() string {
	cmd, err := n.Exec()
	if err != nil {
		return fmt.Sprintf("error building command: %v", err)
	}
	// exec.Cmd.String() is available from Go 1.13 and provides a safe representation
	return cmd.String()
}

// --- Builder Methods ---

// WithPath sets the path to the nsjail binary.
func (n *NsJail) WithPath(path string) *NsJail { n.path = path; return n }

// WithMode sets the execution mode (-M).
func (n *NsJail) WithMode(mode Mode) *NsJail { n.mode = mode; return n }

// WithConfigFile uses a configuration file in ProtoBuf format (-C).
func (n *NsJail) WithConfigFile(path string) *NsJail { n.configFile = path; return n }

// WithExecFile sets the file to exec (-x).
func (n *NsJail) WithExecFile(path string) *NsJail { n.execFile = path; return n }

// EnableExecuteFd uses execveat() to execute a file-descriptor instead of a path (--execute_fd).
func (n *NsJail) EnableExecuteFd() *NsJail { n.executeFd = true; return n }

// WithChroot sets the directory to be the root of the jail (-c).
func (n *NsJail) WithChroot(path string) *NsJail { n.chroot = path; return n }

// EnableNoPivotRoot uses mount(MS_MOVE) and chroot() instead of pivot_root() (--no_pivotroot).
func (n *NsJail) EnableNoPivotRoot() *NsJail { n.noPivotRoot = true; return n }

// MountChrootRW mounts the chroot directory as read-write (--rw). Default is read-only.
func (n *NsJail) MountChrootRW() *NsJail { n.rwChroot = true; return n }

// WithUser sets the user (uid or name) for the jailed process (-u).
func (n *NsJail) WithUser(user string) *NsJail { n.user = user; return n }

// WithGroup sets the group (gid or name) for the jailed process (-g).
func (n *NsJail) WithGroup(group string) *NsJail { n.group = group; return n }

// WithHostname sets the hostname inside the jail (-H).
func (n *NsJail) WithHostname(hostname string) *NsJail { n.hostname = hostname; return n }

// WithCwd sets the working directory inside the jail (-D).
func (n *NsJail) WithCwd(cwd string) *NsJail { n.cwd = cwd; return n }

// WithTimeLimit sets the maximum time in seconds the jail can exist (-t).
func (n *NsJail) WithTimeLimit(seconds uint64) *NsJail { n.timeLimit = seconds; return n }

// Verbose enables verbose logging (-v).
func (n *NsJail) Verbose() *NsJail { n.verbose = true; return n }

// Quiet enables quiet logging, showing only warnings and more important messages (-q).
func (n *NsJail) Quiet() *NsJail { n.quiet = true; return n }

// ReallyQuiet enables logging of fatal messages only (-Q).
func (n *NsJail) ReallyQuiet() *NsJail { n.reallyQuiet = true; return n }

// KeepEnv passes all environment variables to the child process (-e).
func (n *NsJail) KeepEnv() *NsJail { n.keepEnv = true; return n }

// AddEnv adds an environment variable (-E). If value is empty, the current value is inherited.
func (n *NsJail) AddEnv(key, value string) *NsJail {
	if value == "" {
		n.envVars = append(n.envVars, key)
	} else {
		n.envVars = append(n.envVars, fmt.Sprintf("%s=%s", key, value))
	}
	return n
}

// KeepCaps retains all capabilities (--keep_caps).
func (n *NsJail) KeepCaps() *NsJail { n.keepCaps = true; return n }

// AddCap retains a specific capability, e.g., "CAP_PTRACE" (--cap). Can be called multiple times.
func (n *NsJail) AddCap(cap string) *NsJail { n.caps = append(n.caps, cap); return n }

// Silent redirects the child's stdin, stdout, and stderr to /dev/null (--silent).
func (n *NsJail) Silent() *NsJail { n.silent = true; return n }

// StderrToNull redirects the child's stderr to /dev/null (--stderr_to_null).
func (n *NsJail) StderrToNull() *NsJail { n.stderrToNull = true; return n }

// SkipSetsid avoids calling setsid(), allowing for terminal signal handling (--skip_setsid).
func (n *NsJail) SkipSetsid() *NsJail { n.skipSetsid = true; return n }

// AddPassFd keeps a file descriptor open for the child process (--pass_fd). Can be called multiple times.
func (n *NsJail) AddPassFd(fd int) *NsJail { n.passFds = append(n.passFds, fd); return n }

// DisableNoNewPrivs allows the jailed process to gain new privileges (--disable_no_new_privs). DANGEROUS.
func (n *NsJail) DisableNoNewPrivs() *NsJail { n.disableNoNewPrivs = true; return n }

// WithRlimitAs sets RLIMIT_AS in MB (--rlimit_as). Use a number string or a RlimitVal constant.
func (n *NsJail) WithRlimitAs(val string) *NsJail { n.rlimitAs = val; return n }

// WithRlimitCore sets RLIMIT_CORE in MB (--rlimit_core). Use a number string or a RlimitVal constant.
func (n *NsJail) WithRlimitCore(val string) *NsJail { n.rlimitCore = val; return n }

// WithRlimitCpu sets RLIMIT_CPU in seconds (--rlimit_cpu). Use a number string or a RlimitVal constant.
func (n *NsJail) WithRlimitCpu(val string) *NsJail { n.rlimitCpu = val; return n }

// WithRlimitFsize sets RLIMIT_FSIZE in MB (--rlimit_fsize). Use a number string or a RlimitVal constant.
func (n *NsJail) WithRlimitFsize(val string) *NsJail { n.rlimitFsize = val; return n }

// WithRlimitNofile sets RLIMIT_NOFILE (--rlimit_nofile). Use a number string or a RlimitVal constant.
func (n *NsJail) WithRlimitNofile(val string) *NsJail { n.rlimitNofile = val; return n }

// WithRlimitNproc sets RLIMIT_NPROC (--rlimit_nproc). Use a number string or a RlimitVal constant.
func (n *NsJail) WithRlimitNproc(val string) *NsJail { n.rlimitNproc = val; return n }

// WithRlimitStack sets RLIMIT_STACK in MB (--rlimit_stack). Use a number string or a RlimitVal constant.
func (n *NsJail) WithRlimitStack(val string) *NsJail { n.rlimitStack = val; return n }

// WithRlimitMemlock sets RLIMIT_MEMLOCK in KB (--rlimit_memlock). Use a number string or a RlimitVal constant.
func (n *NsJail) WithRlimitMemlock(val string) *NsJail { n.rlimitMemlock = val; return n }

// WithRlimitRtprio sets RLIMIT_RTPRIO (--rlimit_rtprio). Use a number string or a RlimitVal constant.
func (n *NsJail) WithRlimitRtprio(val string) *NsJail { n.rlimitRtprio = val; return n }

// WithRlimitMsgqueue sets RLIMIT_MSGQUEUE in bytes (--rlimit_msgqueue). Use a number string or a RlimitVal constant.
func (n *NsJail) WithRlimitMsgqueue(val string) *NsJail { n.rlimitMsgqueue = val; return n }

// DisableRlimits disables all rlimits, using the parent's limits instead (--disable_rlimits).
func (n *NsJail) DisableRlimits() *NsJail { n.disableRlimits = true; return n }

// EnablePersonaAddrCompatLayout sets personality(ADDR_COMPAT_LAYOUT) (--persona_addr_compat_layout).
func (n *NsJail) EnablePersonaAddrCompatLayout() *NsJail { n.personaAddrCompatLayout = true; return n }

// EnablePersonaMmapPageZero sets personality(MMAP_PAGE_ZERO) (--persona_mmap_page_zero).
func (n *NsJail) EnablePersonaMmapPageZero() *NsJail { n.personaMmapPageZero = true; return n }

// EnablePersonaReadImpliesExec sets personality(READ_IMPLIES_EXEC) (--persona_read_implies_exec).
func (n *NsJail) EnablePersonaReadImpliesExec() *NsJail { n.personaReadImpliesExec = true; return n }

// EnablePersonaAddrLimit3gb sets personality(ADDR_LIMIT_3GB) (--persona_addr_limit_3gb).
func (n *NsJail) EnablePersonaAddrLimit3gb() *NsJail { n.personaAddrLimit3gb = true; return n }

// EnablePersonaAddrNoRandomize sets personality(ADDR_NO_RANDOMIZE) (--persona_addr_no_randomize).
func (n *NsJail) EnablePersonaAddrNoRandomize() *NsJail { n.personaAddrNoRandomize = true; return n }

// DisableCloneNewNet disables the CLONE_NEWNET flag, allowing global network access (-N).
func (n *NsJail) DisableCloneNewNet() *NsJail { n.cloneNewNetDisabled = true; return n }

// DisableCloneNewUser disables CLONE_NEWUSER (--disable_clone_newuser). Requires euid==0.
func (n *NsJail) DisableCloneNewUser() *NsJail { n.cloneNewUserDisabled = true; return n }

// DisableCloneNewNs disables CLONE_NEWNS (--disable_clone_newns).
func (n *NsJail) DisableCloneNewNs() *NsJail { n.cloneNewNsDisabled = true; return n }

// DisableCloneNewPid disables CLONE_NEWPID (--disable_clone_newpid).
func (n *NsJail) DisableCloneNewPid() *NsJail { n.cloneNewPidDisabled = true; return n }

// DisableCloneNewIpc disables CLONE_NEWIPC (--disable_clone_newipc).
func (n *NsJail) DisableCloneNewIpc() *NsJail { n.cloneNewIpcDisabled = true; return n }

// DisableCloneNewUts disables CLONE_NEWUTS (--disable_clone_newuts).
func (n *NsJail) DisableCloneNewUts() *NsJail { n.cloneNewUtsDisabled = true; return n }

// DisableCloneNewCgroup disables CLONE_NEWCGROUP (--disable_clone_newcgroup).
func (n *NsJail) DisableCloneNewCgroup() *NsJail { n.cloneNewCgroupDisabled = true; return n }

// EnableCloneNewTime enables CLONE_NEWTIME (--enable_clone_newtime). Kernel >= 5.3.
func (n *NsJail) EnableCloneNewTime() *NsJail { n.cloneNewTimeEnabled = true; return n }

// AddUidMapping adds a custom uid mapping of the form "inside_uid:outside_uid:count" (-U).
func (n *NsJail) AddUidMapping(mapping string) *NsJail {
	n.uidMappings = append(n.uidMappings, mapping)
	return n
}

// AddGidMapping adds a custom gid mapping of the form "inside_gid:outside_gid:count" (-G).
func (n *NsJail) AddGidMapping(mapping string) *NsJail {
	n.gidMappings = append(n.gidMappings, mapping)
	return n
}

// AddBindMountRO adds a read-only bind mount (-R). Supports 'source' or 'source:dest'.
func (n *NsJail) AddBindMountRO(path string) *NsJail {
	n.bindMountsRO = append(n.bindMountsRO, path)
	return n
}

// AddBindMountRW adds a read-write bind mount (-B). Supports 'source' or 'source:dest'.
func (n *NsJail) AddBindMountRW(path string) *NsJail {
	n.bindMountsRW = append(n.bindMountsRW, path)
	return n
}

// AddTmpfsMount adds a tmpfs mount at the specified destination (-T).
func (n *NsJail) AddTmpfsMount(dest string) *NsJail {
	n.tmpfsMounts = append(n.tmpfsMounts, dest)
	return n
}

// AddMount adds an arbitrary mount point (-m), e.g., AddMount("src", "dst", "type", "options").
func (n *NsJail) AddMount(src, dst, fsType, opts string) *NsJail {
	n.mounts = append(n.mounts, Mount{Src: src, Dst: dst, FsType: fsType, Opts: opts})
	return n
}

// AddSymlink creates a symlink inside the jail (-s), e.g., AddSymlink("src", "dst").
func (n *NsJail) AddSymlink(src, dst string) *NsJail {
	n.symlinks = append(n.symlinks, Symlink{Src: src, Dst: dst})
	return n
}

// DisableProcMount disables mounting procfs in the jail (--disable_proc).
func (n *NsJail) DisableProcMount() *NsJail { n.procMountDisabled = true; return n }

// WithProcPath sets the path to mount procfs (--proc_path). Default is '/proc'.
func (n *NsJail) WithProcPath(path string) *NsJail { n.procPath = path; return n }

// MountProcRW mounts procfs as read-write (--proc_rw). Default is read-only.
func (n *NsJail) MountProcRW() *NsJail { n.procRw = true; return n }

// WithSeccompString uses a kafel seccomp-bpf policy from a string (--seccomp_string).
func (n *NsJail) WithSeccompString(policy string) *NsJail { n.seccompString = policy; return n }

// WithSeccompPolicy uses a kafel seccomp-bpf policy from a file (-P).
func (n *NsJail) WithSeccompPolicy(path string) *NsJail { n.seccompPolicy = path; return n }

// EnableSeccompLog enables logging of seccomp filter actions (--seccomp_log). Kernel >= 4.14.
func (n *NsJail) EnableSeccompLog() *NsJail { n.seccompLog = true; return n }

// WithNiceLevel sets the niceness of the jailed process (--nice_level). Range: -20 (high prio) to 19 (low prio).
func (n *NsJail) WithNiceLevel(level int) *NsJail { n.niceLevel = level; return n }

// WithCgroupMemMax sets the memory cgroup's max bytes (--cgroup_mem_max).
func (n *NsJail) WithCgroupMemMax(bytes uint64) *NsJail { n.cgroupMemMax = bytes; return n }

// WithCgroupMemMemswMax sets the memory cgroup's memory+swap max bytes (--cgroup_mem_memsw_max).
func (n *NsJail) WithCgroupMemMemswMax(bytes uint64) *NsJail { n.cgroupMemMemswMax = bytes; return n }

// WithCgroupMemSwapMax sets the memory cgroup's swap max bytes (--cgroup_mem_swap_max). Use "-1" for unlimited.
func (n *NsJail) WithCgroupMemSwapMax(bytes string) *NsJail { n.cgroupMemSwapMax = bytes; return n }

// WithCgroupMemMount sets the memory cgroup mount point (--cgroup_mem_mount).
func (n *NsJail) WithCgroupMemMount(path string) *NsJail { n.cgroupMemMount = path; return n }

// WithCgroupMemParent sets the parent memory cgroup (--cgroup_mem_parent).
func (n *NsJail) WithCgroupMemParent(parent string) *NsJail { n.cgroupMemParent = parent; return n }

// WithCgroupPidsMax sets the pids cgroup's max number of PIDs (--cgroup_pids_max).
func (n *NsJail) WithCgroupPidsMax(max uint) *NsJail { n.cgroupPidsMax = max; return n }

// WithCgroupPidsMount sets the pids cgroup mount point (--cgroup_pids_mount).
func (n *NsJail) WithCgroupPidsMount(path string) *NsJail { n.cgroupPidsMount = path; return n }

// WithCgroupPidsParent sets the parent pids cgroup (--cgroup_pids_parent).
func (n *NsJail) WithCgroupPidsParent(parent string) *NsJail { n.cgroupPidsParent = parent; return n }

// WithCgroupNetClsClassid sets the net_cls cgroup's class ID (--cgroup_net_cls_classid).
func (n *NsJail) WithCgroupNetClsClassid(id uint32) *NsJail { n.cgroupNetClsClassid = id; return n }

// WithCgroupNetClsMount sets the net_cls cgroup mount point (--cgroup_net_cls_mount).
func (n *NsJail) WithCgroupNetClsMount(path string) *NsJail { n.cgroupNetClsMount = path; return n }

// WithCgroupNetClsParent sets the parent net_cls cgroup (--cgroup_net_cls_parent).
func (n *NsJail) WithCgroupNetClsParent(parent string) *NsJail {
	n.cgroupNetClsParent = parent
	return n
}

// WithCgroupCpuMsPerSec sets the CPU cgroup's milliseconds of CPU time per second (--cgroup_cpu_ms_per_sec).
func (n *NsJail) WithCgroupCpuMsPerSec(ms uint) *NsJail { n.cgroupCpuMsPerSec = ms; return n }

// WithCgroupCpuMount sets the CPU cgroup mount point (--cgroup_cpu_mount).
func (n *NsJail) WithCgroupCpuMount(path string) *NsJail { n.cgroupCpuMount = path; return n }

// WithCgroupCpuParent sets the parent CPU cgroup (--cgroup_cpu_parent).
func (n *NsJail) WithCgroupCpuParent(parent string) *NsJail { n.cgroupCpuParent = parent; return n }

// WithCgroupV2Mount sets the cgroupv2 mount point (--cgroupv2_mount).
func (n *NsJail) WithCgroupV2Mount(path string) *NsJail { n.cgroupv2Mount = path; return n }

// UseCgroupV2 forces the use of cgroup v2 (--use_cgroupv2).
func (n *NsJail) UseCgroupV2() *NsJail { n.useCgroupv2 = true; return n }

// DetectAndUseCgroupV2 automatically uses cgroup v2 if available (--detect_cgroupv2).
func (n *NsJail) DetectAndUseCgroupV2() *NsJail { n.detectCgroupv2 = true; return n }

// DisableLoopbackInterface prevents bringing up the 'lo' interface (--iface_no_lo).
func (n *NsJail) DisableLoopbackInterface() *NsJail { n.ifaceNoLo = true; return n }

// AddOwnInterface moves an existing network interface into the new NET namespace (--iface_own).
func (n *NsJail) AddOwnInterface(iface string) *NsJail {
	n.ifaceOwn = append(n.ifaceOwn, iface)
	return n
}

// WithMacvlanIface clones an interface (MACVLAN) and places it inside the namespace (-I).
func (n *NsJail) WithMacvlanIface(iface string) *NsJail { n.macvlanIface = iface; return n }

// WithMacvlanIp sets the IP for the MACVLAN 'vs' interface (--macvlan_vs_ip).
func (n *NsJail) WithMacvlanIp(ip string) *NsJail { n.macvlanVsIp = ip; return n }

// WithMacvlanNetmask sets the netmask for the MACVLAN 'vs' interface (--macvlan_vs_nm).
func (n *NsJail) WithMacvlanNetmask(nm string) *NsJail { n.macvlanVsNm = nm; return n }

// WithMacvlanGateway sets the gateway for the MACVLAN 'vs' interface (--macvlan_vs_gw).
func (n *NsJail) WithMacvlanGateway(gw string) *NsJail { n.macvlanVsGw = gw; return n }

// WithMacvlanMac sets the MAC address for the MACVLAN 'vs' interface (--macvlan_vs_ma).
func (n *NsJail) WithMacvlanMac(mac string) *NsJail { n.macvlanVsMa = mac; return n }

// WithMacvlanMode sets the mode of the MACVLAN 'vs' interface (--macvlan_vs_mo).
func (n *NsJail) WithMacvlanMode(mode MacVlanMode) *NsJail { n.macvlanVsMo = mode; return n }

// DisableTsc disables RDTSC and RDTSCP instructions (--disable_tsc).
func (n *NsJail) DisableTsc() *NsJail { n.disableTsc = true; return n }

// ForwardSignals forwards fatal signals to the child instead of using SIGKILL (--forward_signals).
func (n *NsJail) ForwardSignals() *NsJail { n.forwardSignals = true; return n }

// WithPort sets the TCP port to bind to (-p), enabling ModeListenTCP.
func (n *NsJail) WithPort(port uint16) *NsJail { n.port = port; return n }

// WithBindhost sets the IP address to bind the listening port to (--bindhost).
func (n *NsJail) WithBindhost(ip string) *NsJail { n.bindhost = ip; return n }

// WithMaxConns sets the maximum number of connections for listen mode (--max_conns).
func (n *NsJail) WithMaxConns(max uint) *NsJail { n.maxConns = max; return n }

// WithMaxConnsPerIp sets the maximum number of connections per IP for listen mode (-i).
func (n *NsJail) WithMaxConnsPerIp(max uint) *NsJail { n.maxConnsPerIp = max; return n }

// WithLogFile sets the log file path (-l).
func (n *NsJail) WithLogFile(path string) *NsJail { n.logFile = path; return n }

// WithLogFd sets the log file descriptor (-L).
func (n *NsJail) WithLogFd(fd int) *NsJail { n.logFd = fd; return n }

// Daemonize runs nsjail as a daemon (-d).
func (n *NsJail) Daemonize() *NsJail { n.daemon = true; return n }

// WithMaxCpus sets the maximum number of CPUs the jailed process can use (--max_cpus).
func (n *NsJail) WithMaxCpus(max uint) *NsJail { n.maxCpus = max; return n }
