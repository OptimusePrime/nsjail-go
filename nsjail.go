// Package nsjail provides a Go wrapper for the NSJail process isolation tool.
// It allows for programmatic configuration and execution of sandboxed processes
// using a fluent builder API.
package nsjail

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// Mode defines the execution mode for NSJail.
type Mode string

const (
	// ModeListenTCP waits for connections on a TCP port.
	ModeListenTCP Mode = "l"
	// ModeOnce launches a single process on the console using clone/execve.
	ModeOnce Mode = "o"
	// ModeExecve launches a single process on the console using execve.
	ModeExecve Mode = "e"
	// ModeRerun launches a single process, and re-runs it forever.
	ModeRerun Mode = "r"
)

// RlimitVal represents a resource limit value, which can be a number or a special string.
type RlimitVal string

const (
	RlimitMax  RlimitVal = "max"
	RlimitHard RlimitVal = "hard"
	RlimitDef  RlimitVal = "def"
	RlimitSoft RlimitVal = "soft"
	RlimitInf  RlimitVal = "inf"
)

// MacVlanMode defines the mode for a MACVLAN interface.
type MacVlanMode string

const (
	MacVlanPrivate  MacVlanMode = "private"
	MacVlanVepa     MacVlanMode = "vepa"
	MacVlanBridge   MacVlanMode = "bridge"
	MacVlanPassthru MacVlanMode = "passthru"
)

// Mount represents a mount point configuration.
type Mount struct {
	Src    string
	Dst    string
	FsType string
	Opts   string
}

// Symlink represents a symbolic link to be created in the jail.
type Symlink struct {
	Src string
	Dst string
}

// NsJail holds the complete configuration for a single NSJail execution.
type NsJail struct {
	// Path to the nsjail binary. Defaults to "nsjail".
	Path string
	// Command to execute inside the jail.
	ExecCmd string
	// Arguments for the command.
	Args []string

	// Core options
	Mode       Mode
	ConfigFile string
	ExecuteFd  bool

	// Isolation options
	Chroot       string
	NoPivotRoot  bool
	Rw           bool
	User         string
	Group        string
	Hostname     string
	Cwd          string
	KeepEnv      bool
	Env          []string
	KeepCaps     bool
	Caps         []string
	Silent       bool
	StderrToNull bool
	SkipSetsid   bool
	PassFds      []int

	// Namespaces
	DisableCloneNewNet    bool
	DisableCloneNewUser   bool
	DisableCloneNewNs     bool
	DisableCloneNewPid    bool
	DisableCloneNewIpc    bool
	DisableCloneNewUts    bool
	DisableCloneNewCgroup bool
	EnableCloneNewTime    bool
	UidMappings           []string
	GidMappings           []string

	// Resource limits
	TimeLimit         uint64
	MaxCpus           uint
	RlimitAs          RlimitVal
	RlimitCore        RlimitVal
	RlimitCpu         RlimitVal
	RlimitFsize       RlimitVal
	RlimitNofile      RlimitVal
	RlimitNproc       RlimitVal
	RlimitStack       RlimitVal
	RlimitMemlock     RlimitVal
	RlimitRtprio      RlimitVal
	RlimitMsgqueue    RlimitVal
	DisableRlimits    bool
	DisableNoNewPrivs bool

	// Mounts
	BindMountsRO []string
	BindMountsRW []string
	TmpfsMounts  []string
	Mounts       []Mount
	Symlinks     []Symlink
	DisableProc  bool
	ProcPath     string
	ProcRw       bool

	// Network options
	Port          uint16
	Bindhost      string
	MaxConns      uint
	MaxConnsPerIp uint
	IfaceNoLo     bool
	IfaceOwn      []string

	// MACVLAN options
	MacvlanIface string
	MacvlanVsIp  string
	MacvlanVsNm  string
	MacvlanVsGw  string
	MacvlanVsMa  string
	MacvlanVsMo  MacVlanMode

	// Seccomp
	SeccompPolicy string
	SeccompString string
	SeccompLog    bool

	// Cgroups
	CgroupMemMax        uint64
	CgroupMemMemswMax   uint64
	CgroupMemSwapMax    string // Can be -1
	CgroupMemMount      string
	CgroupMemParent     string
	CgroupPidsMax       uint
	CgroupPidsMount     string
	CgroupPidsParent    string
	CgroupNetClsClassid uint32
	CgroupNetClsMount   string
	CgroupNetClsParent  string
	CgroupCpuMsPerSec   uint
	CgroupCpuMount      string
	CgroupCpuParent     string
	Cgroupv2Mount       string
	UseCgroupv2         bool
	DetectCgroupv2      bool

	// Other
	LogFile        string
	LogFd          int
	Daemon         bool
	Verbose        bool
	Quiet          bool
	ReallyQuiet    bool
	NiceLevel      int
	DisableTsc     bool
	ForwardSignals bool
}

// New creates a new NsJail configuration for the given command and arguments.
// The path to the nsjail binary defaults to "nsjail" and can be overridden with WithPath().
func New(cmd string, args ...string) *NsJail {
	return &NsJail{
		Path:      "nsjail",
		ExecCmd:   cmd,
		Args:      args,
		LogFd:     -1,   // Use -1 to indicate not set, default is 2
		NiceLevel: -255, // Use magic number to indicate not set
	}
}

// Exec builds the final exec.Cmd object based on the NsJail configuration.
// This allows the caller to manage stdin/stdout/stderr and how the process is run.
func (n *NsJail) Exec() (*exec.Cmd, error) {
	args := []string{}

	// Helper to append flag and value if value is not zero
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

	// Build arguments
	appendFlag("--mode", string(n.Mode))
	appendFlag("--config", n.ConfigFile)
	appendFlagBool("--execute_fd", n.ExecuteFd)
	appendFlag("--chroot", n.Chroot)
	appendFlagBool("--no_pivotroot", n.NoPivotRoot)
	appendFlagBool("--rw", n.Rw)
	appendFlag("--user", n.User)
	appendFlag("--group", n.Group)
	appendFlag("--hostname", n.Hostname)
	appendFlag("--cwd", n.Cwd)
	appendFlagBool("--keep_env", n.KeepEnv)
	appendFlagSlice("--env", n.Env)
	appendFlagBool("--keep_caps", n.KeepCaps)
	appendFlagSlice("--cap", n.Caps)
	appendFlagBool("--silent", n.Silent)
	appendFlagBool("--stderr_to_null", n.StderrToNull)
	appendFlagBool("--skip_setsid", n.SkipSetsid)
	for _, fd := range n.PassFds {
		args = append(args, "--pass_fd", strconv.Itoa(fd))
	}

	// Namespaces
	appendFlagBool("--disable_clone_newnet", n.DisableCloneNewNet)
	appendFlagBool("--disable_clone_newuser", n.DisableCloneNewUser)
	appendFlagBool("--disable_clone_newns", n.DisableCloneNewNs)
	appendFlagBool("--disable_clone_newpid", n.DisableCloneNewPid)
	appendFlagBool("--disable_clone_newipc", n.DisableCloneNewIpc)
	appendFlagBool("--disable_clone_newuts", n.DisableCloneNewUts)
	appendFlagBool("--disable_clone_newcgroup", n.DisableCloneNewCgroup)
	appendFlagBool("--enable_clone_newtime", n.EnableCloneNewTime)
	appendFlagSlice("--uid_mapping", n.UidMappings)
	appendFlagSlice("--gid_mapping", n.GidMappings)

	// Resources
	appendFlagUint64("--time_limit", n.TimeLimit)
	appendFlagUint("--max_cpus", n.MaxCpus)
	appendFlag("--rlimit_as", string(n.RlimitAs))
	appendFlag("--rlimit_core", string(n.RlimitCore))
	appendFlag("--rlimit_cpu", string(n.RlimitCpu))
	appendFlag("--rlimit_fsize", string(n.RlimitFsize))
	appendFlag("--rlimit_nofile", string(n.RlimitNofile))
	appendFlag("--rlimit_nproc", string(n.RlimitNproc))
	appendFlag("--rlimit_stack", string(n.RlimitStack))
	appendFlag("--rlimit_memlock", string(n.RlimitMemlock))
	appendFlag("--rlimit_rtprio", string(n.RlimitRtprio))
	appendFlag("--rlimit_msgqueue", string(n.RlimitMsgqueue))
	appendFlagBool("--disable_rlimits", n.DisableRlimits)
	appendFlagBool("--disable_no_new_privs", n.DisableNoNewPrivs)

	// Mounts
	appendFlagSlice("--bindmount_ro", n.BindMountsRO)
	appendFlagSlice("--bindmount", n.BindMountsRW)
	appendFlagSlice("--tmpfsmount", n.TmpfsMounts)
	for _, m := range n.Mounts {
		mountStr := fmt.Sprintf("%s:%s:%s:%s", m.Src, m.Dst, m.FsType, m.Opts)
		args = append(args, "--mount", mountStr)
	}
	for _, s := range n.Symlinks {
		symlinkStr := fmt.Sprintf("%s:%s", s.Src, s.Dst)
		args = append(args, "--symlink", symlinkStr)
	}
	appendFlagBool("--disable_proc", n.DisableProc)
	appendFlag("--proc_path", n.ProcPath)
	appendFlagBool("--proc_rw", n.ProcRw)

	// Network
	if n.Port > 0 {
		args = append(args, "--port", strconv.Itoa(int(n.Port)))
	}
	appendFlag("--bindhost", n.Bindhost)
	appendFlagUint("--max_conns", n.MaxConns)
	appendFlagUint("--max_conns_per_ip", n.MaxConnsPerIp)
	appendFlagBool("--iface_no_lo", n.IfaceNoLo)
	appendFlagSlice("--iface_own", n.IfaceOwn)

	// MACVLAN
	appendFlag("-I", n.MacvlanIface)
	appendFlag("--macvlan_vs_ip", n.MacvlanVsIp)
	appendFlag("--macvlan_vs_nm", n.MacvlanVsNm)
	appendFlag("--macvlan_vs_gw", n.MacvlanVsGw)
	appendFlag("--macvlan_vs_ma", n.MacvlanVsMa)
	appendFlag("--macvlan_vs_mo", string(n.MacvlanVsMo))

	// Seccomp
	appendFlag("--seccomp_policy", n.SeccompPolicy)
	appendFlag("--seccomp_string", n.SeccompString)
	appendFlagBool("--seccomp_log", n.SeccompLog)

	// Cgroups
	appendFlagUint64("--cgroup_mem_max", n.CgroupMemMax)
	appendFlagUint64("--cgroup_mem_memsw_max", n.CgroupMemMemswMax)
	if n.CgroupMemSwapMax != "" {
		args = append(args, "--cgroup_mem_swap_max", n.CgroupMemSwapMax)
	}
	appendFlag("--cgroup_mem_mount", n.CgroupMemMount)
	appendFlag("--cgroup_mem_parent", n.CgroupMemParent)
	appendFlagUint("--cgroup_pids_max", n.CgroupPidsMax)
	appendFlag("--cgroup_pids_mount", n.CgroupPidsMount)
	appendFlag("--cgroup_pids_parent", n.CgroupPidsParent)
	if n.CgroupNetClsClassid > 0 {
		args = append(args, "--cgroup_net_cls_classid", fmt.Sprintf("0x%x", n.CgroupNetClsClassid))
	}
	appendFlag("--cgroup_net_cls_mount", n.CgroupNetClsMount)
	appendFlag("--cgroup_net_cls_parent", n.CgroupNetClsParent)
	appendFlagUint("--cgroup_cpu_ms_per_sec", n.CgroupCpuMsPerSec)
	appendFlag("--cgroup_cpu_mount", n.CgroupCpuMount)
	appendFlag("--cgroup_cpu_parent", n.CgroupCpuParent)
	appendFlag("--cgroupv2_mount", n.Cgroupv2Mount)
	appendFlagBool("--use_cgroupv2", n.UseCgroupv2)
	appendFlagBool("--detect_cgroupv2", n.DetectCgroupv2)

	// Other
	appendFlag("--log", n.LogFile)
	if n.LogFd != -1 {
		args = append(args, "--log_fd", strconv.Itoa(n.LogFd))
	}
	appendFlagBool("--daemon", n.Daemon)
	appendFlagBool("--verbose", n.Verbose)
	appendFlagBool("--quiet", n.Quiet)
	appendFlagBool("--really_quiet", n.ReallyQuiet)
	if n.NiceLevel != -255 {
		args = append(args, "--nice_level", strconv.Itoa(n.NiceLevel))
	}
	appendFlagBool("--disable_tsc", n.DisableTsc)
	appendFlagBool("--forward_signals", n.ForwardSignals)

	// Command and its arguments
	args = append(args, "--")
	args = append(args, n.ExecCmd)
	args = append(args, n.Args...)

	// Create command
	cmd := exec.Command(n.Path, args...)
	return cmd, nil
}

// String returns the string representation of the command to be executed.
func (n *NsJail) String() string {
	cmd, err := n.Exec()
	if err != nil {
		return fmt.Sprintf("error building command: %v", err)
	}
	return strings.Join(cmd.Args, " ")
}
