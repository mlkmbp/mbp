package api

import (
	"github.com/gin-gonic/gin"
	"mlkmbp/mbp/common"
	stdnet "net" // 避免与 gopsutil/net 混淆
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	gnet "github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

/*
********** 版本信息（可通过 -ldflags 注入） ***********
go build -ldflags "

	-X 'main.BuildVersion=1.2.3'

"
如果可执行包名不是 main，请把 main. 改成正确的包名路径。
*****************************************************
*/
var (
	BuildVersion = "latest"
)

/*********** 监控器实例 ***********/
var sysMonitor = NewSysMonitor()

type netSample struct {
	Rx uint64
	Tx uint64
}

type SysInfoResp struct {
	Timestamp int64 `json:"timestamp"`

	App struct {
		StartAt     int64     `json:"start_at"` // 应用启动时间(ms)
		Version     string    `json:"version"`
		User        bool      `json:"user"`
		Rule        bool      `json:"rule"`
		Pve         bool      `json:"pve"`
		RunTime     time.Time `json:"run_time"`     // 超过该时间不可用
		MachineCode string    `json:"machine_code"` // 许可绑定的机器码
		A           string    `json:"a"`
		GoVersion   string    `json:"go_version"`
	} `json:"app"`

	Host struct {
		Hostname       string `json:"hostname"`
		OS             string `json:"os"`
		Platform       string `json:"platform"`
		PlatformFamily string `json:"platform_family"`
		PlatformVer    string `json:"platform_version"`
		KernelVersion  string `json:"kernel_version"`
		Arch           string `json:"arch"`
		Uptime         uint64 `json:"uptime"`
		BootTime       uint64 `json:"boot_time"`
		Virtualization string `json:"virtualization"`
	} `json:"host"`

	CPU struct {
		ModelName  string    `json:"model_name"`
		Cores      int       `json:"cores"`
		Physical   int       `json:"physical"`
		Mhz        float64   `json:"mhz"`
		UsageTotal float64   `json:"usage_total"`
		UsagePer   []float64 `json:"usage_per"`
		Load1      float64   `json:"load1"`
		Load5      float64   `json:"load5"`
		Load15     float64   `json:"load15"`
	} `json:"cpu"`

	Memory struct {
		Total       uint64  `json:"total"`
		Used        uint64  `json:"used"`
		UsedPercent float64 `json:"used_percent"`
		Free        uint64  `json:"free"`
		Buffers     uint64  `json:"buffers"`
		Cached      uint64  `json:"cached"`
	} `json:"memory"`

	Swap struct {
		Total       uint64  `json:"total"`
		Used        uint64  `json:"used"`
		Free        uint64  `json:"free"`
		UsedPercent float64 `json:"used_percent"`
	} `json:"swap"`

	Disks []struct {
		Device      string  `json:"device"`
		Mountpoint  string  `json:"mountpoint"`
		Fstype      string  `json:"fstype"`
		Total       uint64  `json:"total"`
		Used        uint64  `json:"used"`
		Free        uint64  `json:"free"`
		UsedPercent float64 `json:"used_percent"`
	} `json:"disks"`

	DiskIO struct {
		ReadBytes  uint64 `json:"read_bytes"`
		WriteBytes uint64 `json:"write_bytes"`
		ReadCount  uint64 `json:"read_count"`
		WriteCount uint64 `json:"write_count"`
	} `json:"disk_io_total"`

	Net []struct {
		Name     string `json:"name"`
		IP       string `json:"ip"`
		MAC      string `json:"mac"`
		RxBytes  uint64 `json:"rx_bytes"` // 系统累计
		TxBytes  uint64 `json:"tx_bytes"` // 系统累计
		RxBps    uint64 `json:"rx_bps"`   // 采样速率
		TxBps    uint64 `json:"tx_bps"`
		MTU      int    `json:"mtu"`
		Up       bool   `json:"up"`
		Internal bool   `json:"internal"`
	} `json:"net"`

	NetTotal struct {
		RxBytes uint64 `json:"rx_bytes"`
		TxBytes uint64 `json:"tx_bytes"`
		RxBps   uint64 `json:"rx_bps"`
		TxBps   uint64 `json:"tx_bps"`
	} `json:"net_total"`

	Processes struct {
		Count int `json:"count"`
	} `json:"processes"`

	Sockets struct {
		TCP int `json:"tcp_connections"`
		UDP int `json:"udp_sockets"`
	} `json:"sockets"`
}

type SysMonitor struct {
	mu         sync.Mutex
	lastAt     time.Time
	lastIfMap  map[string]netSample
	lastTotal  netSample
	appStartAt time.Time
}

func NewSysMonitor() *SysMonitor {
	return &SysMonitor{
		lastAt:     time.Now(),
		lastIfMap:  map[string]netSample{},
		appStartAt: time.Now(),
	}
}

func firstIPv4(addrs []gnet.InterfaceAddr) string {
	for _, a := range addrs {
		if a.Addr == "" {
			continue
		}
		plain := a.Addr
		if i := strings.IndexByte(plain, '/'); i > 0 {
			plain = plain[:i]
		}
		ip := stdnet.ParseIP(plain)
		if ip != nil && ip.To4() != nil {
			return plain
		}
	}
	return ""
}

func (m *SysMonitor) Snapshot() (*SysInfoResp, error) {
	now := time.Now()

	// 基本信息
	hi, _ := host.Info()
	vm, _ := mem.VirtualMemory()
	sw, _ := mem.SwapMemory()
	ld, _ := load.Avg()

	// CPU
	cpuInfos, _ := cpu.Info()
	logical, _ := cpu.Counts(true)
	physical, _ := cpu.Counts(false)
	perPerCore, _ := cpu.Percent(0, true)
	var usageTotal float64
	if len(perPerCore) > 0 {
		var sum float64
		for _, v := range perPerCore {
			sum += v
		}
		usageTotal = sum / float64(len(perPerCore))
	}

	// 磁盘分区
	parts, _ := disk.Partitions(true)

	// 全盘 IO 累计
	dio, _ := disk.IOCounters()
	var rb, wb, rc, wc uint64
	for _, v := range dio {
		rb += v.ReadBytes
		wb += v.WriteBytes
		rc += v.ReadCount
		wc += v.WriteCount
	}

	// 网络采样
	ifStats, _ := gnet.IOCounters(true) // 每个网卡累计
	ifaces, _ := gnet.Interfaces()

	m.mu.Lock()
	defer m.mu.Unlock()

	elapsed := now.Sub(m.lastAt).Seconds()
	if elapsed <= 0 {
		elapsed = 1
	}
	if m.lastIfMap == nil {
		m.lastIfMap = map[string]netSample{}
	}

	resp := &SysInfoResp{Timestamp: now.UnixMilli()}

	// App
	resp.App.StartAt = m.appStartAt.UnixMilli()
	resp.App.Version = BuildVersion
	have, _ := common.StableMachineID()
	resp.App.A = have
	resp.App.GoVersion = runtime.Version()

	// Host
	resp.Host.Hostname = hi.Hostname
	resp.Host.OS = hi.OS
	resp.Host.Platform = hi.Platform
	resp.Host.PlatformFamily = hi.PlatformFamily
	resp.Host.PlatformVer = hi.PlatformVersion
	resp.Host.KernelVersion = hi.KernelVersion
	resp.Host.Arch = runtime.GOARCH
	resp.Host.Uptime = hi.Uptime
	resp.Host.BootTime = hi.BootTime
	resp.Host.Virtualization = hi.VirtualizationSystem

	// CPU
	resp.CPU.Cores = logical
	resp.CPU.Physical = physical
	if len(cpuInfos) > 0 {
		resp.CPU.ModelName = cpuInfos[0].ModelName
		resp.CPU.Mhz = cpuInfos[0].Mhz
	}
	resp.CPU.UsageTotal = usageTotal
	resp.CPU.UsagePer = perPerCore
	if ld != nil {
		resp.CPU.Load1, resp.CPU.Load5, resp.CPU.Load15 = ld.Load1, ld.Load5, ld.Load15
	}

	// Memory
	resp.Memory.Total = vm.Total
	resp.Memory.Used = vm.Used
	resp.Memory.Free = vm.Available
	resp.Memory.UsedPercent = vm.UsedPercent
	resp.Memory.Buffers = vm.Buffers
	resp.Memory.Cached = vm.Cached

	// Swap
	resp.Swap.Total = sw.Total
	resp.Swap.Used = sw.Used
	resp.Swap.Free = sw.Free
	resp.Swap.UsedPercent = sw.UsedPercent

	// Disks
	for _, p := range parts {
		du, err := disk.Usage(p.Mountpoint)
		if err != nil {
			continue
		}
		resp.Disks = append(resp.Disks, struct {
			Device      string  `json:"device"`
			Mountpoint  string  `json:"mountpoint"`
			Fstype      string  `json:"fstype"`
			Total       uint64  `json:"total"`
			Used        uint64  `json:"used"`
			Free        uint64  `json:"free"`
			UsedPercent float64 `json:"used_percent"`
		}{
			Device: p.Device, Mountpoint: du.Path, Fstype: p.Fstype,
			Total: du.Total, Used: du.Used, Free: du.Free, UsedPercent: du.UsedPercent,
		})
	}

	// Disk IO 合计
	resp.DiskIO.ReadBytes = rb
	resp.DiskIO.WriteBytes = wb
	resp.DiskIO.ReadCount = rc
	resp.DiskIO.WriteCount = wc

	// 每个网卡 & 速率
	for _, s := range ifStats {
		prev, ok := m.lastIfMap[s.Name]
		var drx, dtx uint64
		if ok {
			if s.BytesRecv >= prev.Rx {
				drx = s.BytesRecv - prev.Rx
			}
			if s.BytesSent >= prev.Tx {
				dtx = s.BytesSent - prev.Tx
			}
		}
		rxbps := uint64(float64(drx) / elapsed)
		txbps := uint64(float64(dtx) / elapsed)

		// 接口属性
		ip := ""
		mac := ""
		mtu := 0
		up := false
		internal := false
		for _, inf := range ifaces {
			if inf.Name != s.Name {
				continue
			}
			ip = firstIPv4(inf.Addrs)
			mac = inf.HardwareAddr
			mtu = int(inf.MTU)
			for _, f := range inf.Flags {
				if strings.EqualFold(f, "up") {
					up = true
				}
				if strings.Contains(strings.ToLower(f), "loopback") {
					internal = true
				}
			}
			break
		}
		if !up {
			continue
		}

		resp.Net = append(resp.Net, struct {
			Name     string `json:"name"`
			IP       string `json:"ip"`
			MAC      string `json:"mac"`
			RxBytes  uint64 `json:"rx_bytes"`
			TxBytes  uint64 `json:"tx_bytes"`
			RxBps    uint64 `json:"rx_bps"`
			TxBps    uint64 `json:"tx_bps"`
			MTU      int    `json:"mtu"`
			Up       bool   `json:"up"`
			Internal bool   `json:"internal"`
		}{
			Name: s.Name, IP: ip, MAC: mac,
			RxBytes: s.BytesRecv, TxBytes: s.BytesSent, // 系统累计
			RxBps: rxbps, TxBps: txbps,
			MTU: mtu, Up: up, Internal: internal,
		})

		// 更新样本
		m.lastIfMap[s.Name] = netSample{Rx: s.BytesRecv, Tx: s.BytesSent}
	}

	// 合计（排除 loopback）
	var totalRx, totalTx uint64
	for _, s := range ifStats {
		n := strings.ToLower(s.Name)
		if strings.HasPrefix(n, "lo") || strings.Contains(n, "loopback") {
			continue
		}
		totalRx += s.BytesRecv
		totalTx += s.BytesSent
	}
	// 速率（合计）
	var drxTot, dtxTot uint64
	if totalRx >= m.lastTotal.Rx {
		drxTot = totalRx - m.lastTotal.Rx
	}
	if totalTx >= m.lastTotal.Tx {
		dtxTot = totalTx - m.lastTotal.Tx
	}
	resp.NetTotal.RxBytes = totalRx
	resp.NetTotal.TxBytes = totalTx
	resp.NetTotal.RxBps = uint64(float64(drxTot) / elapsed)
	resp.NetTotal.TxBps = uint64(float64(dtxTot) / elapsed)

	m.lastTotal = netSample{Rx: totalRx, Tx: totalTx}
	m.lastAt = now

	// 进程 / 连接（没有权限时忽略错误）
	if pids, err := process.Pids(); err == nil {
		resp.Processes.Count = len(pids)
	}
	if tcp, err := gnet.Connections("tcp"); err == nil {
		resp.Sockets.TCP = len(tcp)
	}
	if udp, err := gnet.Connections("udp"); err == nil {
		resp.Sockets.UDP = len(udp)
	}

	return resp, nil
}

/*********** 控制器 ***********/
func (s *Server) systemInfo(c *gin.Context) {
	resp, err := sysMonitor.Snapshot()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	resp.App.User = s.App.Cfg.License.User
	resp.App.Rule = s.App.Cfg.License.Rule
	resp.App.Pve = s.App.Cfg.License.Pve
	resp.App.RunTime = s.App.Cfg.License.RunTime
	resp.App.MachineCode = s.App.Cfg.License.MachineCode
	c.JSON(http.StatusOK, resp)
}
