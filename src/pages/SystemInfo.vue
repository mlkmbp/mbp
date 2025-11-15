<script setup lang="ts">
import { ref, onMounted, onBeforeUnmount, nextTick } from 'vue'
import api from '../api'
import * as echarts from 'echarts'

/* ================= 容量格式化 ================= */
// 磁盘/内存：1024 进制
function formatIEC(n?: number) {
  const v = Number(n || 0)
  if (!Number.isFinite(v) || v <= 0) return '-'
  const u = ['B','KiB','MiB','GiB','TiB','PiB']
  let i = 0, x = v
  while (x >= 1024 && i < u.length - 1) { x /= 1024; i++ }
  const num = x >= 100 ? Math.round(x) : +x.toFixed(2)
  return `${num} ${u[i]}`
}
// 网络“累计”：1000 进制
function formatSIBytes(n?: number) {
  const v = Number(n || 0)
  if (!Number.isFinite(v) || v <= 0) return '-'
  const u = ['B','KB','MB','GB','TB','PB']
  let i = 0, x = v
  while (x >= 1000 && i < u.length - 1) { x /= 1000; i++ }
  const num = x >= 100 ? Math.round(x) : +x.toFixed(2)
  return `${num} ${u[i]}`
}

/* ================== 数据类型 ================== */
type NetRow = {
  name: string
  ip: string
  mac?: string
  rx_bytes: number
  tx_bytes: number
  rx_bps: number   // 注意：后端字段名叫 bps，但可能是 B/s；下面会统一归一化
  tx_bps: number
  mtu?: number
  up?: boolean
  internal?: boolean
}
type DiskRow = {
  device: string
  mountpoint: string
  fstype: string
  total: number
  used: number
  free: number
  used_percent: number
}
interface SysInfo {
  timestamp: number
  app?: {
    start_at: number
    version?: string
    user?: string
    rule?: string
    pve?: string
    run_time?: number
    machine_code?: string
    a?: string
    go_version?: string
  }
  host: {
    hostname: string
    os: string
    platform: string
    arch: string
    uptime: number
    boot_time: number
    platform_family?: string
    platform_version?: string
    kernel_version?: string
    virtualization?: string
  }
  cpu: {
    model_name?: string
    cores: number
    physical?: number
    mhz?: number
    usage_total: number
    usage_per: number[]
    load1: number
    load5: number
    load15: number
  }
  memory: {
    total: number
    used: number
    used_percent: number
    free: number
    buffers?: number
    cached?: number
  }
  swap: {
    total: number
    used: number
    used_percent: number
    free: number
  }
  disks: DiskRow[]
  disk_io_total?: { read_bytes: number; write_bytes: number; read_count: number; write_count: number }
  net: NetRow[]
  net_total?: { rx_bytes: number; tx_bytes: number; rx_bps: number; tx_bps: number }
  processes?: { count: number }
  sockets?: { tcp_connections: number; udp_sockets: number }
}

/* ================== 配置：后端速率输入单位 ================== */
const NIC_INPUT_UNIT:   'bytes' | 'bits' = 'bytes'
const TOTAL_INPUT_UNIT: 'bytes' | 'bits' = 'bytes'

function toBitsPerSecond(v: number, input: 'bytes'|'bits') {
  return (v || 0) * (input === 'bytes' ? 8 : 1)
}

/* ================== 速率单位与迟滞 ================== */
type BitStep = { unit: 'bps' | 'Kbps' | 'Mbps' | 'Gbps' | 'Tbps'; factor: number }
const BIT_STEPS: BitStep[] = [
  { unit: 'bps',  factor: 1 },
  { unit: 'Kbps', factor: 1_000 },
  { unit: 'Mbps', factor: 1_000_000 },
  { unit: 'Gbps', factor: 1_000_000_000 },
  { unit: 'Tbps', factor: 1_000_000_000_000 },
]
function pickBitUnit(maxBps: number): BitStep {
  let step = BIT_STEPS[0]
  for (const s of BIT_STEPS) if (maxBps >= s.factor) step = s
  return step
}
const UP_RATIO = 1.15   // 上行阈值（>115% 才升一级）
const DOWN_RATIO = 0.75 // 下行阈值（<75%  才降一级）
function updateUnitWithHysteresis(prev: BitStep, maxRawBps: number): BitStep {
  const target = pickBitUnit(maxRawBps)
  if (target.factor > prev.factor && maxRawBps >= target.factor * UP_RATIO) return target
  if (target.factor < prev.factor && maxRawBps <= prev.factor * DOWN_RATIO) return target
  return prev
}
function digitsOf(val: number) { return val >= 100 ? 0 : val >= 10 ? 1 : 2 }
function niceCeil(n: number): number {
  if (!Number.isFinite(n) || n <= 0) return 1
  const p = Math.pow(10, Math.floor(Math.log10(n)))
  const d = n / p
  const m = d <= 1 ? 1 : d <= 2 ? 2 : d <= 5 ? 5 : 10
  return m * p
}

/* ================== 小屏判定 ================== */
const isSmall = ref(typeof window !== 'undefined' ? window.innerWidth <= 600 : false)
function handleResize() { isSmall.value = window.innerWidth <= 600; resizeCharts() }

/* ================== CPU/MEM/SWAP ================== */
let cpuChart: echarts.ECharts | null = null
let memChart: echarts.ECharts | null = null
let swapChart: echarts.ECharts | null = null
const cpuSeries: number[] = []
const xLabels: string[] = []
function pushCpuPoint(ts: number, cpu: number) {
  const label = new Date(ts).toLocaleTimeString()
  cpuSeries.push(Number(cpu.toFixed(1)))
  xLabels.push(label)
  while (cpuSeries.length > 90) cpuSeries.shift()
  while (xLabels.length  > 90) xLabels.shift()
  cpuChart?.setOption({ xAxis: { data: xLabels }, series: [{ data: cpuSeries }] })
}

/* ================== 每网卡一图 ================== */
type NetSeriesStore = {
  labels: string[]
  rxRaw: number[]  // 原始 bit/s（已统一×8）
  txRaw: number[]
  step: BitStep
}
const NET_MAX_POINTS = 90
const netCharts = new Map<string, echarts.ECharts>()
const netSeries = new Map<string, NetSeriesStore>()
function safeId(name: string) { return 'net_' + name.replace(/[^\w]/g, '_') }

function ensureNetChart(name: string) {
  if (netCharts.has(name)) return
  const el = document.getElementById(safeId(name))
  if (!el) return
  const chart = echarts.init(el)

  // 用 formatter（不是 valueFormatter），这样能拿到“当前网卡”的 step
  chart.setOption({
    tooltip: {
      trigger: 'axis',
      confine: true,
      formatter: (params: any) => {
        const st = netSeries.get(name)
        if (!st) return ''
        const arr = Array.isArray(params) ? params : [params]
        const lines = arr.map((p: any) => {
          const v = Number(p.value)                     // 这是“已按 step 缩放后的值”
          return `${p.marker}${p.seriesName}: ${v.toFixed(digitsOf(v))} ${st.step.unit}`
        })
        return `${arr[0]?.axisValueLabel || ''}<br/>` + lines.join('<br/>')
      }
    },
    legend: { data: ['Rx','Tx'] },
    xAxis: { type: 'category', data: [] },
    yAxis: {
      type: 'value',
      name: 'bps', // 会在更新时换成实际单位
      min: 0,
      axisLabel: { formatter: (v: number) => v.toString() }, // 已缩放，只显示数字
    },
    grid: { left: 44, right: 12, top: 26, bottom: 26 },
    series: [
      { name: 'Rx', type: 'line', smooth: true, areaStyle: {}, showSymbol: false, data: [] },
      { name: 'Tx', type: 'line', smooth: true, areaStyle: {}, showSymbol: false, data: [] },
    ],
  })
  netCharts.set(name, chart)
  if (!netSeries.has(name)) netSeries.set(name, { labels: [], rxRaw: [], txRaw: [], step: BIT_STEPS[0] })
}

function removeStaleNetCharts(currentNames: Set<string>) {
  for (const [name, chart] of netCharts.entries()) {
    if (!currentNames.has(name)) {
      chart.dispose()
      netCharts.delete(name)
      netSeries.delete(name)
    }
  }
}

function pushNetPoint(ts: number, nets: NetRow[]) {
  const label = new Date(ts).toLocaleTimeString()
  const nameSet = new Set<string>(nets.map(n => n.name))
  removeStaleNetCharts(nameSet)

  nextTick(() => {
    for (const n of nets) ensureNetChart(n.name)

    for (const n of nets) {
      const st = netSeries.get(n.name)!
      // 统一转 bit/s
      const rxBps = toBitsPerSecond(n.rx_bps, NIC_INPUT_UNIT)
      const txBps = toBitsPerSecond(n.tx_bps, NIC_INPUT_UNIT)

      st.labels.push(label)
      st.rxRaw.push(Math.max(0, rxBps))
      st.txRaw.push(Math.max(0, txBps))
      while (st.labels.length > NET_MAX_POINTS) { st.labels.shift(); st.rxRaw.shift(); st.txRaw.shift() }

      // 峰值（bit/s）+ 迟滞选择单位
      const rawMax = Math.max(1, ...st.rxRaw, ...st.txRaw)
      st.step = updateUnitWithHysteresis(st.step, rawMax)

      // 缩放数据（按单位因子）
      const f = st.step.factor
      const rxScaled = st.rxRaw.map(v => v / f)
      const txScaled = st.txRaw.map(v => v / f)
      const yMax = niceCeil(Math.max(1, ...rxScaled, ...txScaled) * 1.15)

      const chart = netCharts.get(n.name)
      chart?.setOption({
        xAxis: { data: st.labels },
        yAxis: { name: st.step.unit, max: yMax, axisLabel: { formatter: (v: number) => v.toString() } },
        series: [{ data: rxScaled }, { data: txScaled }],
      })
    }
  })
}

/* ================== 网络合计（独立单位与迟滞） ================== */
const netTotalStep = ref<BitStep>(BIT_STEPS[0])
function fmtNetTotalCurrent(total?: {rx_bps:number; tx_bps:number}) {
  if (!total) return '- / -'
  const rx = toBitsPerSecond(total.rx_bps || 0, TOTAL_INPUT_UNIT)
  const tx = toBitsPerSecond(total.tx_bps || 0, TOTAL_INPUT_UNIT)
  const peak = Math.max(rx, tx, 1)
  netTotalStep.value = updateUnitWithHysteresis(netTotalStep.value, peak)
  const f = netTotalStep.value.factor
  const rxS = rx / f, txS = tx / f
  return `${rxS.toFixed(digitsOf(rxS))} ${netTotalStep.value.unit} / ${txS.toFixed(digitsOf(txS))} ${netTotalStep.value.unit}`
}

/* ================== 其它 ================== */
const info = ref<SysInfo | null>(null)
let timer: any = null
function humanizeSeconds(sec: number): string {
  let s = Math.max(0, Math.floor(sec || 0))
  const d = Math.floor(s/86400); s -= d*86400
  const h = Math.floor(s/3600);  s -= h*3600
  const m = Math.floor(s/60);    s -= m*60
  const parts: string[] = []
  if (d) parts.push(`${d}天`)
  if (h) parts.push(`${h}小时`)
  if (m) parts.push(`${m}分`)
  if (!d && !h && !m) parts.push(`${s}秒`)
  return parts.join(' ')
}

/* ================== 初始化/拉取 ================== */
function initCharts() {
  cpuChart = echarts.init(document.getElementById('cpu-line') as HTMLElement)
  cpuChart.setOption({
    tooltip: { trigger: 'axis', confine: true },
    xAxis: { type: 'category', data: xLabels },
    yAxis: { type: 'value', name: 'CPU %', min: 0, max: 100, axisLabel: { formatter: (v:number)=>`${v}%` } },
    grid: { left: 44, right: 12, top: 26, bottom: 26 },
    series: [{ type: 'line', data: cpuSeries, smooth: true, areaStyle: {}, showSymbol: false }],
  })

  memChart = echarts.init(document.getElementById('mem-gauge') as HTMLElement)
  memChart.setOption({
    series: [{ type: 'gauge', min: 0, max: 100, detail: { formatter: '{value}%' }, data: [{ value: 0, name: '内存占用' }] }]
  })

  swapChart = echarts.init(document.getElementById('swap-gauge') as HTMLElement)
  swapChart.setOption({
    series: [{ type: 'gauge', min: 0, max: 100, detail: { formatter: '{value}%' }, data: [{ value: 0, name: 'Swap 占用' }] }]
  })

  window.addEventListener('resize', handleResize)
  window.addEventListener('orientationchange', handleResize)
}
function resizeCharts() {
  cpuChart?.resize(); memChart?.resize(); swapChart?.resize()
  for (const ch of netCharts.values()) ch.resize()
}

async function pullOnce() {
  const { data } = await api.get('/systemInfo')
  info.value = data as SysInfo

  // CPU
  pushCpuPoint(data.timestamp, data.cpu.usage_total)

  // 内存/Swap
  memChart?.setOption({ series: [{ data: [{ value: Number(data.memory.used_percent.toFixed(1)), name: '内存占用' }] }] })
  swapChart?.setOption({ series: [{ data: [{ value: Number(data.swap.used_percent.toFixed(1)), name: 'Swap 占用' }] }] })

  // 网卡
  const nets: NetRow[] = (data.net || [])
  pushNetPoint(data.timestamp, nets)
}

onMounted(async () => {
  initCharts()
  await pullOnce()
  timer = setInterval(pullOnce, 3000)
})
onBeforeUnmount(() => {
  clearInterval(timer); timer = null
  window.removeEventListener('resize', handleResize)
  window.removeEventListener('orientationchange', handleResize)
  cpuChart?.dispose(); memChart?.dispose(); swapChart?.dispose()
  for (const ch of netCharts.values()) ch.dispose()
  netCharts.clear(); netSeries.clear()
})
</script>

<template>
  <!-- Row 0: Host / App / NetTotal 合计 -->
  <el-row :gutter="12" style="margin-bottom:12px;">
    <el-col :xs="24" :sm="12" :lg="10">
      <el-card>
        <template #header>主机信息</template>
        <div v-if="info">
          <div>主机名：{{ info.host.hostname }}</div>
          <div>系统：{{ info.host.platform }} / {{ info.host.os }} / {{ info.host.arch }}</div>
          <div v-if="info.host.platform_family">家族：{{ info.host.platform_family }}</div>
          <div v-if="info.host.platform_version">版本：{{ info.host.platform_version }}</div>
          <div v-if="info.host.kernel_version">内核：{{ info.host.kernel_version }}</div>
          <div v-if="info.host.virtualization">虚拟化：{{ info.host.virtualization }}</div>
          <div>Uptime：{{ humanizeSeconds(info.host.uptime) }}</div>
          <div>Boot：{{ new Date(info.host.boot_time * 1000).toLocaleString() }}</div>
        </div>
      </el-card>
    </el-col>

    <el-col :xs="24" :sm="12" :lg="7">
      <el-card>
        <template #header>应用</template>
        <div v-if="info?.app">
          <div>启动：{{ new Date(info.app.start_at).toLocaleString() }}</div>
          <div v-if="info.app.version">版本：{{ info.app.version }}</div>
          <div v-if="info.app.user">用户状态：{{ info.app.user }}</div>
          <div v-if="info.app.rule">规则状态：{{ info.app.rule }}</div>
          <div v-if="info.app.pve">PVE 状态：{{ info.app.pve }}</div>
          <div v-if="info.app.run_time">过期时间：{{ new Date(info.app.run_time).toLocaleString() }}</div>
          <div v-if="info.app.machine_code">授权机器码：{{ info.app.machine_code }}</div>
          <div v-if="info.app.a">机器码：{{ info.app.a }}</div>
        </div>
        <div v-else>—</div>
      </el-card>
    </el-col>

    <el-col :xs="24" :sm="24" :lg="7">
      <el-card>
        <template #header>网络合计（非 loopback）</template>
        <div v-if="info?.net_total">
          <div>累计：{{ formatSIBytes(info.net_total.rx_bytes) }} / {{ formatSIBytes(info.net_total.tx_bytes) }}</div>
          <div>当前：{{ fmtNetTotalCurrent(info.net_total) }}</div>
        </div>
        <div v-else>—</div>
      </el-card>
    </el-col>
  </el-row>

  <!-- Row 1: CPU / 进程&连接 + 磁盘 IO 累计 -->
  <el-row :gutter="12">
    <el-col :xs="24" :sm="24" :lg="12">
      <el-card>
        <template #header>CPU（总）</template>
        <div id="cpu-line" :style="{height: isSmall ? '200px' : '260px'}"></div>
        <div v-if="info" style="display:flex;gap:8px;flex-wrap:wrap;">
          <el-tag type="info">型号：{{ info.cpu.model_name || '-' }}</el-tag>
          <el-tag>逻辑核：{{ info.cpu.cores }}</el-tag>
          <el-tag v-if="info.cpu.physical">物理核：{{ info.cpu.physical }}</el-tag>
          <el-tag v-if="info.cpu.mhz">频率：{{ info.cpu.mhz }} MHz</el-tag>
          <el-tag type="success">Load1: {{ info.cpu.load1.toFixed(2) }}</el-tag>
          <el-tag type="success">Load5: {{ info.cpu.load5.toFixed(2) }}</el-tag>
          <el-tag type="success">Load15: {{ info.cpu.load15.toFixed(2) }}</el-tag>
        </div>
      </el-card>
    </el-col>

    <el-col :xs="24" :sm="24" :lg="12">
      <el-card>
        <template #header>进程 / 连接统计</template>
        <div v-if="info" style="display:flex;gap:10px;flex-wrap:wrap;">
          <el-tag type="warning">进程数：{{ info.processes?.count ?? '-' }}</el-tag>
          <el-tag type="success">TCP：{{ info.sockets?.tcp_connections ?? '-' }}</el-tag>
          <el-tag type="info">UDP：{{ info.sockets?.udp_sockets ?? '-' }}</el-tag>
        </div>
      </el-card>

      <el-card style="margin-top:12px;">
        <template #header>磁盘累计 IO</template>
        <div v-if="info?.disk_io_total">
          <div>读取：{{ formatIEC(info.disk_io_total.read_bytes) }}（{{ info.disk_io_total.read_count }} 次）</div>
          <div>写入：{{ formatIEC(info.disk_io_total.write_bytes) }}（{{ info.disk_io_total.write_count }} 次）</div>
        </div>
        <div v-else>—</div>
      </el-card>
    </el-col>
  </el-row>

  <!-- Row 2: 内存 + Swap -->
  <el-row :gutter="12" style="margin-top:12px;">
    <el-col :xs="24" :sm="24" :lg="12">
      <el-card>
        <template #header>内存占用</template>
        <div id="mem-gauge" :style="{height: isSmall ? '180px' : '220px'}"></div>
        <div v-if="info" style="display:flex;gap:8px;flex-wrap:wrap;">
          <el-tag>总计：{{ formatIEC(info.memory.total) }}</el-tag>
          <el-tag type="warning">已用：{{ formatIEC(info.memory.used) }}</el-tag>
          <el-tag type="info">可用：{{ formatIEC(info.memory.free) }}</el-tag>
          <el-tag v-if="info.memory.cached">Cached：{{ formatIEC(info.memory.cached) }}</el-tag>
          <el-tag v-if="info.memory.buffers">Buffers：{{ formatIEC(info.memory.buffers) }}</el-tag>
        </div>
      </el-card>
    </el-col>

    <el-col :xs="24" :sm="24" :lg="12">
      <el-card>
        <template #header>Swap 占用</template>
        <div id="swap-gauge" :style="{height: isSmall ? '180px' : '220px'}"></div>
        <div v-if="info" style="display:flex;gap:8px;flex-wrap:wrap;">
          <el-tag>总计：{{ formatIEC(info.swap.total) }}</el-tag>
          <el-tag type="warning">已用：{{ formatIEC(info.swap.used) }}</el-tag>
          <el-tag type="info">可用：{{ formatIEC(info.swap.free) }}</el-tag>
        </div>
      </el-card>
    </el-col>
  </el-row>

  <!-- Row 3: 每个网卡一个图 -->
  <el-row :gutter="12" style="margin-top:12px;">
    <el-col :xs="24" :sm="24" :lg="12" v-for="n in (info?.net || [])" :key="n.name">
      <el-card>
        <template #header>网卡 {{ n.name }}（{{ n.ip || '-' }}）</template>
        <div :id="safeId(n.name)" :style="{height: isSmall ? '180px' : '220px'}"></div>
        <div style="margin-top:8px;display:flex;gap:8px;flex-wrap:wrap;">
          <el-tag type="info">MAC：{{ n.mac || '-' }}</el-tag>
          <el-tag>MTU：{{ n.mtu ?? '-' }}</el-tag>
          <el-tag :type="n.up ? 'success' : 'info'">{{ n.up ? 'UP' : 'DOWN' }}</el-tag>
          <el-tag>累计：{{ formatSIBytes(n.rx_bytes) }} / {{ formatSIBytes(n.tx_bytes) }}</el-tag>
          <el-tag type="warning">
            当前：
            {{
              (() => {
                const st = netSeries.get(n.name)
                if (!st) return '- / -'
                const rxS = toBitsPerSecond(n.rx_bps, NIC_INPUT_UNIT) / st.step.factor
                const txS = toBitsPerSecond(n.tx_bps, NIC_INPUT_UNIT) / st.step.factor
                return `${rxS.toFixed(digitsOf(rxS))} ${st.step.unit} / ${txS.toFixed(digitsOf(txS))} ${st.step.unit}`
              })()
            }}
          </el-tag>
        </div>
      </el-card>
    </el-col>
  </el-row>

  <!-- Row 4: 磁盘分区 -->
  <el-row :gutter="12" style="margin-top:12px;">
    <el-col :span="24">
      <el-card>
        <template #header>磁盘分区 - 仅供参考</template>
        <div class="table-scroll">
          <el-table v-if="info" :data="info.disks" size="small" :height="isSmall ? 360 : 500" class="minw-900">
            <el-table-column prop="device" label="设备" width="180" />
            <el-table-column prop="mountpoint" label="挂载点" width="180" />
            <el-table-column label="总/已用/可用" min-width="260">
              <template #default="{ row }">
                {{ formatIEC(row.total) }} / {{ formatIEC(row.used) }} / {{ formatIEC(row.free) }}
              </template>
            </el-table-column>
            <el-table-column prop="fstype" label="FS" width="140" />
            <el-table-column prop="used_percent" label="使用率" width="200">
              <template #default="{ row }">
                <el-progress :percentage="Number(row.used_percent.toFixed(1))" />
              </template>
            </el-table-column>
          </el-table>
        </div>
      </el-card>
    </el-col>
  </el-row>
</template>

<style scoped>
.el-card { border-radius: 14px; }
.table-scroll{ width:100%; overflow-x:auto; }
.minw-900{ min-width:900px; }
</style>
