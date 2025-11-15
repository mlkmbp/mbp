<script setup lang="ts">
import { ref, computed, onMounted, onBeforeUnmount, nextTick, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import * as echarts from 'echarts'
import api from '../api'

/* ============== 基本与路由 ============== */
const route = useRoute()
const router = useRouter()
const vmid = computed(() => Number(route.params.vmid))

/* ============== 小工具 ============== */
function formatIEC(n?: number) {
  const v = Number(n || 0)
  if (!Number.isFinite(v) || v <= 0) return '-'
  const u = ['B','KiB','MiB','GiB','TiB','PiB']
  let i = 0, x = v
  while (x >= 1024 && i < u.length - 1) { x /= 1024; i++ }
  const num = x >= 100 ? Math.round(x) : +x.toFixed(2)
  return `${num} ${u[i]}`
}
function formatSI(n?: number) {
  const v = Number(n || 0)
  if (!Number.isFinite(v) || v <= 0) return '-'
  const u = ['B','KB','MB','GB','TB','PB']
  let i = 0, x = v
  while (x >= 1000 && i < u.length - 1) { x /= 1000; i++ }
  const num = x >= 100 ? Math.round(x) : +x.toFixed(2)
  return `${num} ${u[i]}`
}
function pct(n?: number) {
  if (n == null || !Number.isFinite(n)) return null
  return Math.max(0, Math.min(100, +n.toFixed(1)))
}
function humanize(s?: number) {
  let t = Math.max(0, Math.floor(s || 0))
  const d = Math.floor(t/86400); t -= d*86400
  const h = Math.floor(t/3600);  t -= h*3600
  const m = Math.floor(t/60);    t -= m*60
  const arr:string[] = []
  if (d) arr.push(`${d}天`); if (h) arr.push(`${h}小时`); if (m) arr.push(`${m}分`)
  if (!d && !h && !m) arr.push(`${t}秒`)
  return arr.join(' ')
}

/* ============== 数据模型 ============== */
type BlockStat = {
  rd_bytes?: number; rd_operations?: number;
  wr_bytes?: number; wr_operations?: number;
  flush_operations?: number; unmap_bytes?: number;
  wr_highest_offset?: number;
}
type VmSummary = {
  status?: string
  type?: 'qemu'|'lxc'
  node?: string
  name?: string
  uptime?: number
  lock?: string
  cpu?: number
  cpus?: number
  maxmem?: number
  mem?: number
  maxdisk?: number
  disk?: number
  netin?: number
  netout?: number
  diskwrite?: number
  diskread?: number
  balloon?: number
  ballooninfo?: { actual?: number; max_mem?: number; total_mem?: number; free_mem?: number }
  nics?: Record<string, { netin?: number; netout?: number }>
  blockstat?: Record<string, BlockStat>
  'running-qemu'?: string
  'running-machine'?: string
  qmpstatus?: string
  freemem?: number
  pid?: number
  ha?: { managed?: 0|1 }
  'proxmox-support'?: Record<string, boolean|string>
}
type VmConfig = Record<string, any>

const summary = ref<VmSummary>({})
const config  = ref<VmConfig>({})

/* ============== 加载状态 ============== */
const loadingSummary = ref(false)
const loadingConfig  = ref(false)

/* —— 顶部动作的 loading（开关机/重启/停止） —— */
const acting = ref(false)

/* —— 对话框 + 各自 loading —— */
const reinstallDlg = ref(false)
const resetPwdDlg  = ref(false)
const sshDlg       = ref(false)

const loadingReinstall = ref(false)
const loadingResetPwd  = ref(false)
const loadingSSH       = ref(false)

const loadingISO       = ref(false)
const loadingTemplate  = ref(false)

/* ============== 拉数据 ============== */
async function loadSummary() {
  if (!vmid.value) return
  loadingSummary.value = true
  try {
    const { data } = await api.get(`/pve/vm/${vmid.value}/summary`, { headers: { 'Cache-Control': 'no-cache', 'X-Silent': '1' } })
    summary.value = data || {}
  } catch {
    try {
      const { data } = await api.get(`/pve/vm/${vmid.value}/status`, { headers: { 'Cache-Control': 'no-cache', 'X-Silent': '1' } })
      summary.value = data || {}
    } catch {}
  } finally { loadingSummary.value = false }
}
async function loadConfig() {
  if (!vmid.value) return
  loadingConfig.value = true
  try {
    const { data } = await api.get(`/pve/vm/${vmid.value}/config`)
    config.value = data || {}
  } catch {} finally { loadingConfig.value = false }
}

/* ============== 派生 ============== */
const power     = computed(() => String(summary.value?.status || 'unknown').toLowerCase())
const isRunning = computed(() => power.value === 'running')
const isStopped = computed(() => power.value === 'stopped')
const kind      = computed(() => String(summary.value?.type || '').toLowerCase())

const cpuPct = computed(() => summary.value?.cpu == null ? null : pct(summary.value!.cpu! * 100))
const memPct = computed(() => {
  const m = summary.value?.mem, M = summary.value?.maxmem
  if (!M || m == null) return null
  return pct((m / M) * 100)
})
const diskPct = computed(() => {
  const d = summary.value?.disk, D = summary.value?.maxdisk
  if (!D || d == null) return null
  return pct((d / D) * 100)
})
const diskIO = computed(() => ({ read: summary.value?.diskread ?? 0, write: summary.value?.diskwrite ?? 0 }))
const nicRuntime = computed(() => summary.value?.nics || {})
const featureTags = computed(() => {
  const ps = summary.value?.['proxmox-support'] || {}
  const list:{k:string; v:boolean|string}[] = []
  for (const [k,v] of Object.entries(ps)) if (v === true || typeof v === 'string') list.push({k, v})
  return list
})
const balloonText = computed(() => {
  const b = summary.value?.ballooninfo
  const cap = summary.value?.balloon
  if (!b && !cap) return null
  const parts:string[] = []
  if (cap) parts.push(`上限 ${formatIEC(cap)}`)
  if (b?.actual != null) parts.push(`当前 ${formatIEC(b.actual)}`)
  if (b?.total_mem != null) parts.push(`来宾总内存 ${formatIEC(b.total_mem)}`)
  if (b?.free_mem != null) parts.push(`来宾空闲 ${formatIEC(b.free_mem)}`)
  return parts.join('，')
})

/* ============== 顶部动作 ============== */
async function postAction(path: string, body: any = {}) {
  acting.value = true
  try {
    await api.post(`/pve/vm/${vmid.value}/${path}`, body)
    ElMessage.success('操作已提交')
    setTimeout(loadSummary, 800)
  } catch (e:any) {
    // ElMessage.error(e?.response?.data?.error || e?.message || '操作失败')
    throw e
  } finally { acting.value = false }
}
async function onStart()    { await postAction('start') }
async function onShutdown() { await ElMessageBox.confirm('确定优雅关机？','确认',{type:'warning'}); await postAction('shutdown') }
async function onStop()     { await ElMessageBox.confirm('确定强制停止（相当于断电）？','确认',{type:'warning'}); await postAction('stop') }
async function onReboot()   { await ElMessageBox.confirm('确定重启？','确认',{type:'warning'}); await postAction('reboot') }
function openVNC() {
  const href = router.resolve({ name: 'vnc', params: { vmid: vmid.value } }).href
  window.open(href, '_blank', 'noopener,noreferrer')
}

/* ============== RRD ============== */
type RPoint = {
  t:number; cpu?:number; mem?:number; maxmem?:number; disk?:number; maxdisk?:number;
  netin?:number; netout?:number; diskread?:number; diskwrite?:number
}
const range = ref<'1h'|'24h'|'7d'>('1h')
const autoRefresh = ref(true)
let timer:any = null
let chartCPU: echarts.ECharts | null = null
let chartMEM: echarts.ECharts | null = null
let chartDISK: echarts.ECharts | null = null
let chartNET: echarts.ECharts | null = null
let chartIO:  echarts.ECharts | null = null
const rrd = ref<RPoint[]>([])
const rrdLoading = ref(false)
const tfMap: Record<string, string> = { '1h': 'hour', '24h': 'day', '7d': 'week' }

const chartsWrap = ref<HTMLElement | null>(null)
let ro: ResizeObserver | null = null
function safeResize() { requestAnimationFrame(() => requestAnimationFrame(() => resizeCharts())) }
function timeLabel(t: number) { return new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) }
function parseRRD(raw:any): RPoint[] {
  const arr:any[] = Array.isArray(raw) ? raw : (raw?.data ?? raw?.points ?? [])
  const out:RPoint[] = []
  for (const p of arr) {
    const t0 = p.time ?? p.ts ?? p.t ?? p._time
    if (t0 == null) continue
    const t = Number(t0) > 1e12 ? Number(t0) : Number(t0) * 1000
    let cpuPct: number | undefined
    const vcpu = p.cpu != null ? Number(p.cpu) : undefined
    if (vcpu != null) cpuPct = vcpu <= 1 ? vcpu * 100 : vcpu
    out.push({
      t,
      cpu: cpuPct,
      mem: p.mem != null ? Number(p.mem) : undefined,
      maxmem: p.maxmem != null ? Number(p.maxmem) : undefined,
      disk: p.disk != null ? Number(p.disk) : undefined,
      maxdisk: p.maxdisk != null ? Number(p.maxdisk) : undefined,
      netin: p.netin != null ? Number(p.netin) : undefined,
      netout: p.netout != null ? Number(p.netout) : undefined,
      diskread: p.diskread != null ? Number(p.diskread) : undefined,
      diskwrite: p.diskwrite != null ? Number(p.diskwrite) : undefined,
    })
  }
  out.sort((a,b)=>a.t-b.t)
  return out
}
async function loadRRD() {
  if (!vmid.value || !isRunning.value) return
  rrdLoading.value = true
  try {
    const { data } = await api.get(`/pve/vm/${vmid.value}/rrd`, { params: { timeframe: tfMap[range.value] } })
    rrd.value = parseRRD(data)
    await nextTick()
    drawRRD()
    safeResize()
  } catch {} finally { rrdLoading.value = false }
}
function initCharts() {
  const cpuEl  = document.getElementById('c-cpu')
  const memEl  = document.getElementById('c-mem')
  const diskEl = document.getElementById('c-disk')
  const netEl  = document.getElementById('c-net')
  const ioEl   = document.getElementById('c-io')
  if (!cpuEl || !memEl || !diskEl || !netEl || !ioEl) return

  chartCPU  = echarts.init(cpuEl)
  chartMEM  = echarts.init(memEl)
  chartDISK = echarts.init(diskEl)
  chartNET  = echarts.init(netEl)
  chartIO   = echarts.init(ioEl)

  const basePct = (fmt:(v:number)=>string) => ({
    tooltip:{ trigger:'axis', confine:true, valueFormatter:(v:any)=> typeof v==='number'?fmt(v):'-' },
    grid:{ left:40, right:8, top:24, bottom:24, containLabel:true },
    xAxis:{ type:'category', boundaryGap:false, data:[], axisLabel:{ hideOverlap:true, margin:10 } },
    yAxis:{ type:'value', name:'', axisLabel:{ formatter:(v:number)=>fmt(v) } },
    series:[{ type:'line', smooth:true, showSymbol:false, areaStyle:{}, data:[] }]
  })
  chartCPU.setOption(basePct(v=>`${v.toFixed(1)}%`))
  chartMEM.setOption(basePct(v=>`${v.toFixed(1)}%`))
  chartDISK.setOption(basePct(v=>`${v.toFixed(1)}%`))

  chartNET.setOption({
    tooltip:{ trigger:'axis', confine:true, valueFormatter:(v:any)=> formatSI(v)+'/s' },
    legend:{ data:['接收','发送'], top:2, right:8 },
    grid:{ left:40, right:8, top:30, bottom:24, containLabel:true },
    xAxis:{ type:'category', boundaryGap:false, data:[], axisLabel:{ hideOverlap:true, margin:10 } },
    yAxis:{ type:'value', name:'', axisLabel:{ formatter:(v:number)=> formatSI(v).replace(' ','') } },
    series:[
      { name:'接收', type:'line', smooth:true, showSymbol:false, areaStyle:{}, data:[] },
      { name:'发送', type:'line', smooth:true, showSymbol:false, areaStyle:{}, data:[] },
    ],
  })
  chartIO.setOption({
    tooltip:{ trigger:'axis', confine:true, valueFormatter:(v:any)=> formatSI(v)+'/s' },
    legend:{ data:['读','写'], top:2, right:8 },
    grid:{ left:40, right:8, top:30, bottom:24, containLabel:true },
    xAxis:{ type:'category', boundaryGap:false, data:[], axisLabel:{ hideOverlap:true, margin:10 } },
    yAxis:{ type:'value', name:'', axisLabel:{ formatter:(v:number)=> formatSI(v).replace(' ','') } },
    series:[
      { name:'读', type:'line', smooth:true, showSymbol:false, areaStyle:{}, data:[] },
      { name:'写', type:'line', smooth:true, showSymbol:false, areaStyle:{}, data:[] },
    ],
  })

  ro?.disconnect()
  ro = new ResizeObserver(() => safeResize())
  if (chartsWrap.value) ro.observe(chartsWrap.value)

  window.addEventListener('resize', safeResize)
  window.addEventListener('orientationchange', safeResize)
}
function resizeCharts(){ chartCPU?.resize(); chartMEM?.resize(); chartDISK?.resize(); chartNET?.resize(); chartIO?.resize() }
function drawRRD() {
  const labels = rrd.value.map(p => timeLabel(p.t))
  chartCPU?.setOption({ xAxis:{ data: labels }, series:[{ data: rrd.value.map(p => p.cpu == null ? null : +p.cpu!.toFixed(1)) }] })
  chartMEM?.setOption({ xAxis:{ data: labels }, series:[{ data: rrd.value.map(p => (p.maxmem!>0 && p.mem!=null) ? +((p.mem!/p.maxmem!)*100).toFixed(1) : null) }] })
  chartDISK?.setOption({ xAxis:{ data: labels }, series:[{ data: rrd.value.map(p => (p.maxdisk!>0 && p.disk!=null) ? +((p.disk!/p.maxdisk!)*100).toFixed(1) : null) }] })
  chartNET?.setOption({ xAxis:{ data: labels }, series:[{ data: rrd.value.map(p => p.netin ?? null) }, { data: rrd.value.map(p => p.netout ?? null) }] })
  chartIO?.setOption({  xAxis:{ data: labels }, series:[{ data: rrd.value.map(p => p.diskread ?? null) }, { data: rrd.value.map(p => p.diskwrite ?? null) }] })
}
watch(range, () => loadRRD())

/* ============== 网络 ============== */
type NicRow = { name: string; mac?: string; model?: string; bridge?: string; tag?: string|number; rate?: number; ips?: string[] }
const nics = ref<NicRow[]>([])
function parseNicsFromConfig() {
  const rows: NicRow[] = []
  const cfg: Record<string, any> = (config.value || {}) as any
  Object.keys(cfg).forEach((key) => {
    if (!/^net\d+$/i.test(key)) return
    const raw = String(cfg[key] ?? '').trim()
    if (!raw) return
    const kv: Record<string, string> = {}
    const models: string[] = []
    raw.split(',').map(s => s.trim()).filter(Boolean).forEach(seg => {
      const i = seg.indexOf('=')
      if (i > 0) { kv[seg.slice(0,i).toLowerCase()] = seg.slice(i+1) }
      else { models.push(seg.toLowerCase()) }
    })
    const isLxcStyle = ('name' in kv) || ('hwaddr' in kv) || ('type' in kv)
    const nicName = kv['name'] ? kv['name'] : key
    let model = ''
    if (isLxcStyle) model = kv['type'] || ''
    else {
      const modelKeys = ['virtio','e1000','rtl8139','vmxnet3']
      model = models.find(m => modelKeys.includes(m)) || modelKeys.find(m => kv[m] != null) || (models[0] || '')
    }
    let mac = ''
    if (isLxcStyle) mac = kv['hwaddr'] || ''
    else mac = kv['macaddr'] || ''
    if (mac) mac = mac.toUpperCase()
    const bridge = kv['bridge'] || ''
    const tag = (kv['tag'] ?? '')
    const rate = kv['rate'] != null ? Number(kv['rate']) : undefined
    const ips: string[] = []
    if (isLxcStyle) {
      const ip  = (kv['ip']  || '').toLowerCase()
      const ip6 = (kv['ip6'] || '').toLowerCase()
      if (ip && ip !== 'dhcp') ips.push(kv['ip'])
      if (ip6 && ip6 !== 'auto') ips.push(kv['ip6'])
    }
    rows.push({ name: nicName, mac: mac || undefined, model: model || undefined, bridge: bridge || undefined, tag: tag || undefined, rate, ips: ips.length ? ips : undefined })
  })
  rows.sort((a,b)=> Number((a.name||'').match(/\d+/)?.[0]||0) - Number((b.name||'').match(/\d+/)?.[0]||0) )
  nics.value = rows
}
watch(config, () => parseNicsFromConfig(), { deep: true })

/* ============== 重装（QEMU/LXC） ============== */
type StorageFile = { storage: string; file: string; size: number }
const isoList = ref<StorageFile[]>([])
const tmplList = ref<StorageFile[]>([])

const isoStorages = computed(() => Array.from(new Set(isoList.value.map(i => i.storage))))
const tmplStorages = computed(() => Array.from(new Set(tmplList.value.map(i => i.storage))))
const isoStorage = ref(''); const isoFile = ref('')
const tmplStorage = ref(''); const tmplFile = ref('')

const qemuRootPwd = ref(''); const qemuSSHPubKeys = ref(''); const qemuPwdReadonly = ref(true)
const lxcRootPwd  = ref(''); const lxcSSHPubKeys  = ref(''); const lxcPwdReadonly  = ref(true)
const passNameQemu = 'p_' + Math.random().toString(36).slice(2)
const passName     = 'p_' + Math.random().toString(36).slice(2)

function pwdHint() { return '6-64 位；可用数字/字母/符号；不可包含空白' }
function validatePwd(p: string): string | null {
  if (p == "")  return '密码不能为空'
  if (!p) return null
  if (p.length < 6 || p.length > 64) return '密码长度需 6-64 位'
  if (/\s/.test(p)) return '密码不可包含空白字符'
  return null
}
function sanitizeSSH(raw: string): string[] {
  const re = /^(ssh-(rsa|ed25519)|ecdsa-sha2-nistp(256|384|521))\s+[A-Za-z0-9+/=]+(?:\s+.+)?$/
  const noCR = (raw || '').replace(/\r/g, '')
  return noCR.split('\n').map(l=>l.trim()).filter(l=>l.length && !l.startsWith('#') && re.test(l))
}
const sshCount = computed(() => sanitizeSSH(qemuSSHPubKeys.value).length)

function openReinstall() {
  reinstallDlg.value = true
  if (kind.value === 'qemu') {
    qemuPwdReadonly.value = true
    loadISOList()
  } else {
    lxcPwdReadonly.value = true
    loadTemplateList()
  }
}
async function loadISOList() {
  loadingISO.value = true
  try {
    const { data } = await api.get(`/pve/vm/${vmid.value}/iso-list`)
    isoList.value = Array.isArray(data) ? data : []
    if (!isoStorage.value && isoStorages.value.length) isoStorage.value = isoStorages.value[0]
  } catch (e:any) {
    // ElMessage.error(e?.response?.data?.error || e?.message || '加载 ISO 失败')
  } finally { loadingISO.value = false }
}
async function loadTemplateList() {
  loadingTemplate.value = true
  try {
    const { data } = await api.get(`/pve/vm/${vmid.value}/template-list`)
    tmplList.value = Array.isArray(data) ? data : []
    if (!tmplStorage.value && tmplStorages.value.length) tmplStorage.value = tmplStorages.value[0]
  } catch (e:any) {
    // ElMessage.error(e?.response?.data?.error || e?.message || '加载模板失败')
  } finally { loadingTemplate.value = false }
}
const isoFilesFiltered  = computed(() => isoList.value.filter(i => !isoStorage.value || i.storage === isoStorage.value))
const tmplFilesFiltered = computed(() => tmplList.value.filter(i => !tmplStorage.value || i.storage === tmplStorage.value))

async function submitReinstall() {
  if (loadingReinstall.value) return
  loadingReinstall.value = true
  try {
    const body: any = {}
    if (kind.value === 'qemu') {
      if (!isoStorage.value || !isoFile.value) { ElMessage.error('请选择 ISO'); loadingReinstall.value = false; return }
      body.iso_storage = isoStorage.value
      body.iso_file    = isoFile.value

      if (qemuRootPwd.value) {
        const msg = validatePwd(qemuRootPwd.value)
        if (msg) { ElMessage.error(msg); loadingReinstall.value = false; return }
        body.password = qemuRootPwd.value
      }
      if (qemuSSHPubKeys.value) {
        const lines = sanitizeSSH(qemuSSHPubKeys.value)
        if (!lines.length) { ElMessage.error('SSH 公钥格式不正确'); loadingReinstall.value = false; return }
        body.ssh_pub_keys = lines.join('\n')
      }
    } else {
      if (!tmplStorage.value || !tmplFile.value) { ElMessage.error('请选择模板'); loadingReinstall.value = false; return }
      body.tmpl_storage = tmplStorage.value
      body.tmpl_file    = tmplFile.value

      if (!lxcRootPwd.value && !lxcSSHPubKeys.value) { ElMessage.error('需要 root 密码或 SSH 公钥至少一个'); loadingReinstall.value = false; return }
      const msg = validatePwd(lxcRootPwd.value || '')
      if (lxcRootPwd.value && msg) { ElMessage.error(msg); loadingReinstall.value = false; return }
      if (lxcRootPwd.value)   body.password     = lxcRootPwd.value
      if (lxcSSHPubKeys.value){
        const lines = sanitizeSSH(lxcSSHPubKeys.value)
        if (!lines.length) { ElMessage.error('SSH 公钥格式不正确'); loadingReinstall.value = false; return }
        body.ssh_pub_keys = lines.join('\n')
      }
    }
    await api.post(`/pve/vm/${vmid.value}/reinstall`, body)
    qemuRootPwd.value=''; qemuSSHPubKeys.value=''
    lxcRootPwd.value = ''; lxcSSHPubKeys.value = ''
    reinstallDlg.value = false
    ElMessage.success('已提交重装')
    setTimeout(loadSummary, 1000)
  } catch (e:any) {
    // ElMessage.error(e?.response?.data?.error || e?.message || '提交失败')
  } finally {
    loadingReinstall.value = false
  }
}

/* ============== 重置 root 密码 ============== */
const newPwd = ref(''); const newPwd2 = ref('')
const resetPwdReadonly = ref(true)
const passName2 = 'p_' + Math.random().toString(36).slice(2)
function openResetPwd() { newPwd.value=''; newPwd2.value=''; resetPwdReadonly.value=true; resetPwdDlg.value=true }
async function doResetPwd() {
  if (loadingResetPwd.value) return
  loadingResetPwd.value = true
  try {
    const msg = validatePwd(newPwd.value)
    if (msg) { ElMessage.error(msg); loadingResetPwd.value = false; return }

    if (newPwd.value !== newPwd2.value) { ElMessage.error('两次输入不一致'); loadingResetPwd.value = false; return }
    await api.post(`/pve/vm/${vmid.value}/reset-password`, { password: newPwd.value })
    newPwd.value=''; newPwd2.value=''; resetPwdDlg.value=false
    ElMessage.success('已提交密码重置')
  } catch (e:any) {
    // ElMessage.error(e?.response?.data?.error || e?.message || '提交失败')
  } finally {
    loadingResetPwd.value = false
  }
}

/* ============== 注入 SSH 公钥 ============== */
const sshText = ref('')
function openSSHDialog() {
  sshText.value = String((config.value as any)?.['ssh-public-keys'] || '').trim()
  sshDlg.value = true
}
function sanitizeSSHForDlg(raw: string): string[] {
  const re = /^(ssh-(rsa|ed25519)|ecdsa-sha2-nistp(256|384|521))\s+[A-Za-z0-9+/=]+(?:\s+.+)?$/
  const noCR = (raw || '').replace(/\r/g, '')
  return noCR.split('\n').map(l=>l.trim()).filter(l=>l.length && !l.startsWith('#') && re.test(l))
}
const sshCountDlg2 = computed(() => sanitizeSSHForDlg(sshText.value).length)
async function submitSSH() {
  if (loadingSSH.value) return
  loadingSSH.value = true
  try {
    const lines = sanitizeSSHForDlg(sshText.value)
    if (!lines.length) { ElMessage.error('请粘贴至少一条有效的 OpenSSH 公钥'); loadingSSH.value = false; return }
    await api.post(`/pve/vm/${vmid.value}/reset-ssh-keys`, { ssh_pub_keys: lines.join('\n') })
    sshDlg.value = false
    ElMessage.success('已写入 SSH 公钥（覆盖原值）')
    loadConfig()
  } catch (e:any) {
    // ElMessage.error(e?.response?.data?.error || e?.message || '写入失败')
  } finally {
    loadingSSH.value = false
  }
}

/* ============== 自动刷新 & 布局联动 ============== */
const tab = ref<'summary'|'resource'|'network'>('summary')
function tick() {
  if (!autoRefresh.value) return
  loadSummary()
  if (isRunning.value && tab.value !== 'network') loadRRD()
}
function startTimer(){ stopTimer(); timer = setInterval(tick, 5000) }
function stopTimer(){ if (timer) clearInterval(timer); timer=null }
watch(isRunning, (v) => { if (v) startTimer(); else stopTimer() })
watch(tab, async () => { await nextTick(); safeResize() })
watch(() => [range.value, summary.value?.status], () => safeResize())

onMounted(async () => {
  if (!vmid.value || Number.isNaN(vmid.value)) { ElMessage.error('无效 VMID'); router.replace('/'); return }
  await loadSummary()
  await loadConfig()
  parseNicsFromConfig()
  await nextTick(initCharts)
  await loadRRD()
  startTimer()
})
onBeforeUnmount(() => {
  stopTimer()
  window.removeEventListener('resize', safeResize)
  window.removeEventListener('orientationchange', safeResize)
  ro?.disconnect(); ro = null
  chartCPU?.dispose(); chartMEM?.dispose(); chartDISK?.dispose(); chartNET?.dispose(); chartIO?.dispose()
})
</script>

<template>
  <div class="vm-wrap">
    <!-- 顶部：标题 + 操作 -->
    <div class="top">
      <div class="title">
        <span class="muted">VMID</span>
        <span class="mono">#{{ vmid }}</span>
        <el-tag size="small" :type="isRunning ? 'success' : isStopped ? 'info' : 'warning'" effect="plain">
          {{ summary.status ?? 'unknown' }}
        </el-tag>
        <el-tag size="small" v-if="summary.type">type: {{ (summary.type || '').toUpperCase() }}</el-tag>
        <el-tag size="small" v-if="summary.node">node: {{ summary.node }}</el-tag>
        <el-tag size="small" type="success" v-if="isRunning && summary.uptime">uptime: {{ humanize(summary.uptime) }}</el-tag>
        <el-tag size="small" type="warning" v-if="summary.lock">locked</el-tag>
      </div>

      <div class="actions">
        <div class="actions-buttons">
          <el-button class="act-btn" type="success" :loading="acting" :disabled="isRunning || summary.lock" @click="onStart">开机</el-button>
          <el-button class="act-btn" :loading="acting" :disabled="!isRunning || summary.lock" @click="onReboot">重启</el-button>
          <el-button class="act-btn" type="warning" :loading="acting" :disabled="!isRunning || summary.lock" @click="onShutdown">关机</el-button>
          <el-button class="act-btn" type="danger" :loading="acting" :disabled="!isRunning || summary.lock" @click="onStop">停止</el-button>
          <el-button class="act-btn" type="danger" plain :loading="acting" :disabled="isRunning || summary.lock" @click="openReinstall">重装系统</el-button>
          <el-button class="act-btn" type="primary" :loading="acting" :disabled="!isRunning || summary.lock" @click="openVNC">VNC</el-button>

          <el-button class="act-btn" type="warning" plain :disabled="summary.lock" @click="openResetPwd">重置 root 密码</el-button>
          <el-button class="act-btn" type="warning" plain :disabled="summary.lock" @click="openSSHDialog">重置 SSH 公钥</el-button>
        </div>

        <div class="actions-tools">
          <el-radio-group v-model="range" size="small">
            <el-radio-button label="1h">1小时</el-radio-button>
            <el-radio-button label="24h">24小时</el-radio-button>
            <el-radio-button label="7d">7天</el-radio-button>
          </el-radio-group>
          <el-switch v-model="autoRefresh" active-text="自动刷新" class="ml8" />
          <el-button link class="ml8" @click="loadSummary(); if(isRunning) loadRRD()">刷新</el-button>
        </div>
      </div>
    </div>

    <!-- Tabs -->
    <el-tabs v-model="tab" type="border-card">
      <el-tab-pane label="概要" name="summary">
        <el-descriptions :column="1" size="small" border class="desc">
          <el-descriptions-item label="名称">{{ summary.name ?? '-' }}</el-descriptions-item>
          <el-descriptions-item label="节点">{{ summary.node ?? '-' }}</el-descriptions-item>
          <el-descriptions-item label="类型">{{ (summary.type || '').toUpperCase() || '-' }}</el-descriptions-item>
          <el-descriptions-item label="状态">{{ summary.status ?? '-' }}</el-descriptions-item>
          <el-descriptions-item label="开机时长" v-if="summary.uptime">{{ humanize(summary.uptime) }}</el-descriptions-item>
          <el-descriptions-item label="PID" v-if="summary.pid">{{ summary.pid }}</el-descriptions-item>
          <el-descriptions-item label="HA 托管">{{ summary.ha?.managed ? '是' : '否' }}</el-descriptions-item>
          <el-descriptions-item label="vCPU">{{ summary.cpus ?? '-' }}</el-descriptions-item>
          <el-descriptions-item label="CPU 利用">{{ cpuPct!=null ? `${cpuPct}%` : '-' }}</el-descriptions-item>
          <el-descriptions-item label="内存">
            {{ formatIEC(summary.mem) }} / {{ formatIEC(summary.maxmem) }}
            （{{ memPct!=null?`${memPct}%`:'-' }}）
          </el-descriptions-item>
          <el-descriptions-item label="来宾 Balloon" v-if="balloonText">{{ balloonText }}</el-descriptions-item>
          <el-descriptions-item label="宿主空闲内存" v-if="summary.freemem!=null">{{ formatIEC(summary.freemem) }}</el-descriptions-item>
          <el-descriptions-item label="磁盘">
            {{ formatIEC(summary.disk) }} / {{ formatIEC(summary.maxdisk) }}
            （{{ diskPct!=null?`${diskPct}%`:'-' }}）
          </el-descriptions-item>
          <el-descriptions-item label="磁盘累计 IO">读 {{ formatSI(diskIO.read) }} / 写 {{ formatSI(diskIO.write) }}</el-descriptions-item>
          <el-descriptions-item label="网络累计">↓ {{ formatSI(summary.netin) }} / ↑ {{ formatSI(summary.netout) }}</el-descriptions-item>
          <el-descriptions-item v-if="summary['running-qemu']" label="QEMU">{{ summary['running-qemu'] }}</el-descriptions-item>
          <el-descriptions-item v-if="summary['running-machine']" label="机器">{{ summary['running-machine'] }}</el-descriptions-item>
          <el-descriptions-item v-if="summary.qmpstatus" label="QMP">{{ summary.qmpstatus }}</el-descriptions-item>
        </el-descriptions>

        <el-card style="margin-top:10px;" v-if="featureTags.length">
          <template #header>Proxmox 支持特性</template>
          <div style="display:flex; flex-wrap:wrap; gap:6px;">
            <el-tag v-for="f in featureTags" :key="f.k" size="small" effect="plain">
              {{ f.k }}<template v-if="typeof f.v==='string'">: {{ f.v }}</template>
            </el-tag>
          </div>
        </el-card>

        <div class="charts" ref="chartsWrap" v-show="!isStopped">
          <div class="chart"><div class="chart-title">CPU 使用率（%）</div><div id="c-cpu"  class="ech"></div></div>
          <div class="chart"><div class="chart-title">内存使用率（%）</div><div id="c-mem"  class="ech"></div></div>
          <div class="chart"><div class="chart-title">磁盘使用率（%）</div><div id="c-disk" class="ech"></div></div>
          <div class="chart"><div class="chart-title">网络流量（B/s）</div><div id="c-net" class="ech"></div></div>
          <div class="chart"><div class="chart-title">磁盘 I/O（B/s）</div><div id="c-io" class="ech"></div></div>
        </div>
      </el-tab-pane>

      <el-tab-pane label="资源" name="resource">
        <el-row :gutter="12">
          <el-col :xs="24" :sm="12" :lg="8">
            <el-card><template #header>CPU</template>
              <div>型号：{{ config.cpu ?? '-' }}</div>
              <div>核心：{{ config.cores ?? '-' }} × 插槽：{{ config.sockets ?? 1 }}</div>
              <div v-if="summary.cpus">vCPU：{{ summary.cpus }}</div>
              <el-progress v-if="cpuPct!=null" :percentage="cpuPct" style="margin-top:8px" />
            </el-card>
          </el-col>
          <el-col :xs="24" :sm="12" :lg="8">
            <el-card><template #header>内存</template>
              <div>配置：{{ config.memory ? `${config.memory} MiB` : '-' }} <span v-if="config.balloon">（Balloon: {{ config.balloon }}）</span></div>
              <div>使用：{{ formatIEC(summary.mem) }} / {{ formatIEC(summary.maxmem) }}</div>
              <div v-if="balloonText">Balloon：{{ balloonText }}</div>
              <el-progress v-if="memPct!=null" :percentage="memPct" style="margin-top:8px" />
            </el-card>
          </el-col>
          <el-col :xs="24" :sm="12" :lg="8">
            <el-card><template #header>磁盘</template>
              <div v-for="(v,k) in config" :key="k" v-show="/^(scsi|sata|ide|virtio)\d+$/i.test(k)">
                <span class="mono">{{ k }}</span> = {{ String(v) }}
              </div>
              <div style="margin-top:6px">使用：{{ formatIEC(summary.disk) }} / {{ formatIEC(summary.maxdisk) }}</div>
              <el-progress v-if="diskPct!=null" :percentage="diskPct" style="margin-top:8px" />
            </el-card>
          </el-col>
        </el-row>

        <el-card style="margin-top:12px;" v-if="summary.blockstat && Object.keys(summary.blockstat).length">
          <template #header>块设备统计</template>
          <div class="table-scroll">
            <el-table :data="Object.entries(summary.blockstat).map(([dev, s]) => ({ dev, ...(s || {}) }))" size="small" class="minw-800">
              <el-table-column prop="dev" label="设备" width="120" />
              <el-table-column prop="rd_operations" label="读次数" width="100" />
              <el-table-column prop="wr_operations" label="写次数" width="100" />
              <el-table-column prop="rd_bytes" label="读字节" width="160">
                <template #default="{row}">{{ formatSI(row.rd_bytes) }}</template>
              </el-table-column>
              <el-table-column prop="wr_bytes" label="写字节" width="160">
                <template #default="{row}">{{ formatSI(row.wr_bytes) }}</template>
              </el-table-column>
              <el-table-column prop="flush_operations" label="flush 次数" width="120" />
              <el-table-column prop="unmap_bytes" label="unmap 字节" width="160">
                <template #default="{row}">{{ formatSI(row.unmap_bytes) }}</template>
              </el-table-column>
              <el-table-column prop="wr_highest_offset" label="最高写偏移" min-width="180">
                <template #default="{row}">{{ formatSI(row.wr_highest_offset) }}</template>
              </el-table-column>
            </el-table>
          </div>
        </el-card>
      </el-tab-pane>

      <el-tab-pane label="网络" name="network">
        <div class="table-scroll">
          <el-table :data="nics" size="small" class="minw-800">
            <el-table-column prop="name"  label="网卡" width="120" />
            <el-table-column prop="model" label="型号" width="120" />
            <el-table-column prop="mac"   label="MAC" width="180" />
            <el-table-column prop="bridge" label="桥接" width="140" />
            <el-table-column prop="tag"    label="VLAN" width="100" />
            <el-table-column prop="rate"   label="限速(MB/s)" width="140">
              <template #default="{row}">{{ row.rate ?? '-' }}</template>
            </el-table-column>
            <el-table-column label="IP" min-width="240">
              <template #default="{row}"><span v-if="row.ips?.length">{{ row.ips.join(' / ') }}</span><span v-else>-</span></template>
            </el-table-column>
          </el-table>
        </div>

        <el-card style="margin-top:12px;" v-if="Object.keys(nicRuntime).length">
          <template #header>实时接口统计</template>
          <div class="table-scroll">
            <el-table :data="Object.entries(nicRuntime).map(([name, v]) => ({ name, ...(v || {}) }))" size="small" class="minw-800">
              <el-table-column prop="name"  label="接口" width="180" />
              <el-table-column prop="netin" label="接收累计" width="200"><template #default="{row}">↓ {{ formatSI(row.netin) }}</template></el-table-column>
              <el-table-column prop="netout" label="发送累计" width="200"><template #default="{row}">↑ {{ formatSI(row.netout) }}</template></el-table-column>
            </el-table>
          </div>
        </el-card>
      </el-tab-pane>
    </el-tabs>

    <!-- 重装系统对话框 -->
    <el-dialog v-model="reinstallDlg" title="重装系统" width="640px">
      <div v-loading="loadingReinstall || (kind==='qemu' ? loadingISO : loadingTemplate)">
        <div v-if="kind === 'qemu'">
          <el-form label-width="120px">
            <el-form-item label="ISO 存储">
              <el-select v-model="isoStorage" filterable style="width:260px">
                <el-option v-for="s in isoStorages" :key="s" :label="s" :value="s" />
              </el-select>
            </el-form-item>
            <el-form-item label="ISO 文件">
              <el-select v-model="isoFile" filterable style="width:420px" :disabled="!isoStorage">
                <el-option v-for="i in isoFilesFiltered" :key="i.storage + '|' + i.file" :label="i.file + ' (' + formatIEC(i.size) + ')'" :value="i.file" />
              </el-select>
            </el-form-item>

            <el-form-item label="root 密码">
              <el-input v-model="qemuRootPwd" type="password" :name="passNameQemu" autocomplete="new-password"
                :readonly="qemuPwdReadonly" @focus="qemuPwdReadonly=false" show-password :placeholder="pwdHint() + '（可选）'" />
            </el-form-item>
            <el-form-item label="SSH 公钥">
              <el-input v-model="qemuSSHPubKeys" type="textarea" :rows="3" placeholder="OpenSSH 格式，多行；仅在存在 cloud-init 盘时写入（可选）" />
              <div class="tip" v-if="qemuSSHPubKeys">将写入 {{ sshCount }} 条公钥（若 VM 存在 cloud-init 盘）</div>
            </el-form-item>

            <div class="tip">仅挂载所选 ISO；如填写密码/公钥，将在检测到 <b>cloud-init 盘</b> 时写入。</div>
          </el-form>
        </div>
        <div v-else>
          <el-form label-width="120px">
            <el-form-item label="模板存储">
              <el-select v-model="tmplStorage" filterable style="width:260px">
                <el-option v-for="s in tmplStorages" :key="s" :label="s" :value="s" />
              </el-select>
            </el-form-item>
            <el-form-item label="模板文件">
              <el-select v-model="tmplFile" filterable style="width:420px" :disabled="!tmplStorage">
                <el-option v-for="t in tmplFilesFiltered" :key="t.storage + '|' + t.file" :label="t.file + ' (' + formatIEC(t.size) + ')'" :value="t.file" />
              </el-select>
            </el-form-item>
            <el-form-item label="root 密码">
              <el-input v-model="lxcRootPwd" type="password" :name="passName" autocomplete="new-password"
                :readonly="lxcPwdReadonly" @focus="lxcPwdReadonly=false" show-password :placeholder="pwdHint()+'；或留空用 SSH 公钥'" />
            </el-form-item>
            <el-form-item label="SSH 公钥">
              <el-input v-model="lxcSSHPubKeys" type="textarea" :rows="3" placeholder="OpenSSH 格式，多个用换行分隔；示例：ssh-ed25519 AAAAC3... user@host" />
            </el-form-item>
          </el-form>
        </div>
      </div>
      <template #footer>
        <el-button @click="reinstallDlg = false">取消</el-button>
        <el-button type="primary" :loading="loadingReinstall" @click="submitReinstall">提交</el-button>
      </template>
    </el-dialog>

    <!-- 重置 root 密码 -->
    <el-dialog v-model="resetPwdDlg" title="重置 root 密码" width="520px">
      <div v-loading="loadingResetPwd">
        <el-form label-width="120px">
          <el-form-item label="新密码">
            <el-input v-model="newPwd" type="password" :name="passName2" autocomplete="new-password"
              :readonly="resetPwdReadonly" @focus="resetPwdReadonly = false" show-password :placeholder="pwdHint()" />
          </el-form-item>
          <el-form-item label="确认新密码">
            <el-input v-model="newPwd2" type="password" autocomplete="new-password" show-password placeholder="再次输入新密码" />
          </el-form-item>
        </el-form>
      </div>
      <template #footer>
        <el-button @click="resetPwdDlg = false">取消</el-button>
        <el-button type="primary" :loading="loadingResetPwd" @click="doResetPwd">提交</el-button>
      </template>
    </el-dialog>

    <!-- 注入 SSH 公钥 -->
    <el-dialog v-model="sshDlg" title="注入 SSH 公钥" width="680px">
      <div v-loading="loadingSSH">
        <el-alert type="warning" :closable="false" style="margin-bottom:10px"
          title="将覆盖实例的 SSH 公钥配置（ssh-public-keys）。部分发行版可能需要重启后才完全生效。" />
        <el-form label-width="120px">
          <el-form-item label="公钥（多行）">
            <el-input v-model="sshText" type="textarea" :rows="8" placeholder="每行一条 OpenSSH 公钥，例如：ssh-ed25519 AAAAC3... user@host" />
          </el-form-item>
          <div class="tip">已识别 {{ sshCountDlg2 }} 条有效公钥；支持 ssh-ed25519 / ssh-rsa / ecdsa-sha2-nistp{256,384,521}</div>
        </el-form>
      </div>
      <template #footer>
        <el-button @click="sshDlg = false">取消</el-button>
        <el-button type="primary" :loading="loadingSSH" @click="submitSSH">写入</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.vm-wrap { display:flex; flex-direction:column; gap:12px; padding:10px; overflow-x:hidden; box-sizing:border-box; }
.top { display:flex; flex-direction:column; gap:10px; }
.title { display:flex; align-items:center; gap:8px; flex-wrap:wrap; min-width:0; }
.muted { color: rgba(0,0,0,.55); }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-weight:600; }
.ml8{ margin-left:8px; }

.actions { display:flex; flex-direction:column; gap:8px; }
.actions-buttons { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; }
.act-btn { width: 100%; }
.actions-tools { display:flex; flex-wrap:wrap; align-items:center; gap:8px; }
@media (min-width: 760px) {
  .actions { flex-direction:row; align-items:center; flex-wrap:wrap; }
  .actions-buttons { display:flex; gap:8px; }
  .act-btn { width:auto; }
  .actions-tools { margin-left:auto; }
}

.charts { display:grid; gap:12px; margin-top:12px; grid-template-columns: 1fr; overflow:hidden; }
@media (min-width: 680px) { .charts { grid-template-columns: 1fr 1fr; } }
@media (min-width: 1100px){ .charts { grid-template-columns: 1fr 1fr 1fr 1fr; } }
.chart { background:#fff; border:1px solid #ebeef5; border-radius:10px; padding:8px; min-width:0; }
.chart-title { font-size:13px; color:rgba(0,0,0,.55); margin:0 0 6px 2px; }
.ech { width:100%; max-width:100%; height:220px; display:block; }
@media (max-width: 600px) { .ech { height: 180px; } }

.desc :deep(.el-descriptions__cell) { font-size:13px; }
.table-scroll{ width:100%; overflow-x:auto; }
.minw-800{ min-width:800px; }
.tip { font-size:12px; color:rgba(0,0,0,.6); margin-top:6px; }

:deep(.el-tabs__content) { overflow: visible; }
.el-button+.el-button { margin-left: 0px; }
</style>
