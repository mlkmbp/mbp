<script setup lang="ts"> 
import { inject, ref, type Ref, onMounted, onBeforeUnmount, computed, watch, nextTick } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import type { FormInstance, FormRules } from 'element-plus'
import api from '../api'

const isAdmin = inject<Ref<boolean>>('isAdmin', ref(false))


/* ===================== 类型 ===================== */
interface Rule {
  id: number
  protocol: string
  address: string
  port: number | undefined
  target_address?: string
  target_port?: number | undefined
  up_limit?: number | null          // Bytes/s
  down_limit?: number | null        // Bytes/s
  status: 'enabled' | 'disabled'
  max_connection?: number | null
  conn_timeout?: number | null
  read_timeout?: number | null
  write_timeout?: number | null
  user_id?: number | null
  username?: string | null

  // 新增：可选标识字段
  rule_name?: string | null
  interface_name?: string | null

  // 可选鉴权 & TLS 扩展
  auth_username?: string | null
  auth_password?: string | null
  skip_cert_verify?: boolean | null
  alpn?: string | null
  tls_fingerprint?: string | null

  // 兼容字段（展示/回显）
  TLSCert?: string | null
  TLSKey?: string | null
  TLSSNIGuard?: string | null
  Socks5UDPPort?: number | null
  Socks5BindPort?: number | null
  tls_cert?: string | null
  tls_key?: string | null
  tls_sni_guard?: string | null
  socks5_udp_port?: number | null
  socks5_bind_port?: number | null
  UserID?: number | null
}

interface User { id: number; username: string }

/* ===================== 协议选项 ===================== */
const PROTOCOL_OPTIONS = [
  { value: 'all',        label: 'all（tcp+udp）' },
  { value: 'tcp',        label: 'tcp' },
  { value: 'udp',        label: 'udp' },
  { value: 'tls-tcp',    label: 'tls-tcp' },
  { value: 'http/s',     label: 'http/s' },
  { value: 'tls-http/s', label: 'tls-http/s' },
  { value: 'socks5',     label: 'socks5' },
  { value: 'tls-socks5', label: 'tls-socks5' },
]
function normalizeProtocol(p: any): string {
  const s = String(p || '').trim().replace(/–/g, '-') // 归一化 en-dash
  const hit = PROTOCOL_OPTIONS.find(o => o.value === s)
  return hit ? hit.value : 'all'
}

/* ===================== 速率（Kbps 起） ===================== */
type SpeedUnit = 'Kbps' | 'Mbps' | 'Gbps' | 'Tbps'
const speedUnits: SpeedUnit[] = ['Kbps', 'Mbps', 'Gbps', 'Tbps']
const K10 = 1000
function speedToBps(v: number, unit: SpeedUnit): number {
  const n = Number(v) || 0
  switch (unit) {
    case 'Kbps': return n * K10
    case 'Mbps': return n * (K10 ** 2)
    case 'Gbps': return n * (K10 ** 3)
    case 'Tbps': return n * (K10 ** 4)
  }
  return 0
}
// 阈值分段，避免 log10 带来的边界偏移
function bpsToBestUnitNoBps(bps: number): { value: number; unit: SpeedUnit; lt1K?: boolean } {
  if (!Number.isFinite(bps) || bps <= 0) return { value: 0, unit: 'Kbps', lt1K: true }
  if (bps < 1000) return { value: 0, unit: 'Kbps', lt1K: true } // <1 Kbps
  if (bps < 1_000_000)              return { value: +(bps / 1_000).toFixed(3), unit: 'Kbps' }
  else if (bps < 1_000_000_000)     return { value: +(bps / 1_000_000).toFixed(3), unit: 'Mbps' }
  else if (bps < 1_000_000_000_000) return { value: +(bps / 1_000_000_000).toFixed(3), unit: 'Gbps' }
  else                              return { value: +(bps / 1_000_000_000_000).toFixed(3), unit: 'Tbps' }
}
/** 列表展示：0 => 不限制；null/undefined => '—'；>0 => 带单位 */
function bytesPerSecToBpsLabelDisplay(bytesPerSec?: number | null): string {
  if (bytesPerSec == null) return '—'
  const n = Number(bytesPerSec)
  if (!Number.isFinite(n)) return '—'
  if (n === 0) return '不限制'
  if (n < 0) return '—'
  const r = bpsToBestUnitNoBps(n * 8)
  return r.lt1K ? '<1 Kbps' : `${r.value} ${r.unit}`
}

/* ===================== 列表/查询 ===================== */
const qRuleName = ref('')
const qProtocol = ref('') // 直接用 PROTOCOL_OPTIONS 的 value
const qAddr = ref('')
const qPort = ref<number | ''>('')
const qTAddr = ref('')
const qTPort = ref<number | ''>('')
const qUsername = ref('')
const qStatus = ref<'' | 'enabled' | 'disabled'>('')
const page = ref(1); const size = ref(10)
const total = ref(0); const list = ref<Rule[]>([])
const user = ref<User[]>([])

const dialog = ref(false)
const isEdit = ref(false)
const formRef = ref<FormInstance>()

/* ===================== 表单 ===================== */

const antiFillKey = ref('af_' + Math.random().toString(36).slice(2))

const form = ref<Rule>({
  id: 0,
  protocol: 'all',
  address: '0.0.0.0',
  port: undefined as any,
  target_address: '',
  target_port: undefined as any,

  // 新增：默认空串
  rule_name: '',
  interface_name: '',

  up_limit: null,
  down_limit: null,
  status: 'enabled',
  max_connection: null as any,
  conn_timeout:   null as any,
  read_timeout:   null as any,
  write_timeout:  null as any,
  user_id: undefined,

  auth_username: '',
  auth_password: '',
  skip_cert_verify: false,
  alpn: '',
  tls_fingerprint: '',

  TLSCert: '',
  TLSKey: '',
  TLSSNIGuard: '',
  Socks5UDPPort: null as any,
  Socks5BindPort: null as any,
  UserID: undefined,
} as any)

/* 记录原始“是否固定目标”状态，便于切到动态目标时清理高级项 */
const originalHadFixedTarget = ref(false)

/* ===================== 小屏：弹窗全屏 ===================== */
const isSmallScreen = ref(typeof window !== 'undefined' ? window.innerWidth <= 600 : false)
function onResize(){ isSmallScreen.value = window.innerWidth <= 600 }
onMounted(()=> window.addEventListener('resize', onResize))
onBeforeUnmount(()=> window.removeEventListener('resize', onResize))

/* ===================== 协议判定 ===================== */
const proxyProtocols = ['socks5','tls-socks5','http/s','tls-http/s']
const isTLSHTTPorSOCKS = computed(()=>['tls-socks5','tls-http/s'].includes(String(form.value.protocol).toLowerCase()))
const isTLSTCP = computed(()=> String(form.value.protocol).toLowerCase()==='tls-tcp')
const isSocks5Family = computed(()=>['socks5','tls-socks5'].includes(String(form.value.protocol).toLowerCase()))
const requireTarget = computed(()=>{
  const p = String(form.value.protocol).toLowerCase()
  return p==='all'||p==='tcp'||p==='udp'||p==='tls-tcp'
})
const needTLSCertKey = computed(()=> isTLSHTTPorSOCKS.value || isTLSTCP.value)
const showAdvancedOpts = computed(()=>{
  const p = String(form.value.protocol).toLowerCase()
  const isHttpOrSocks = p==='http/s'||p==='tls-http/s'||p==='socks5'||p==='tls-socks5'
  const addr = (form.value.target_address||'').trim()
  const port = Number(form.value.target_port||0)
  return isHttpOrSocks && !!addr && port>0 && port<=65535
})
// 新增：仅 all/tcp/udp 才显示 interface_name
const showInterfaceName = computed(()=>{
  const p = String(form.value.protocol).toLowerCase()
  return p==='all'||p==='tcp'||p==='udp'
})

/* ===================== 限速输入（UI：Kbps+；存库：Bytes/s） ===================== */
/** 关键：为了支持 clearable，“值”用 string 存（'' 表示留空） */
const upVal   = ref<string>('')      // 显示值
const upUnit  = ref<SpeedUnit>('Mbps')
const downVal = ref<string>('')      // 显示值
const downUnit= ref<SpeedUnit>('Mbps')

/* ===================== 表单校验 ===================== */
const rulesDef = ref<FormRules>({
  protocol: [{ required: true, message: '请选择协议', trigger: 'change' }],
  address:  [{ required: true, message: '请输入监听地址', trigger: 'blur' }],
  port: [
    { required: true, message: '请输入端口', trigger: 'blur' },
    { validator: (_r: any, v: any, cb: (e?:Error)=>void) => {
        const n = Number(v)
        if (!Number.isInteger(n) || n < 1 || n > 65535) return cb(new Error('端口范围 1~65535'))
        cb()
      }, trigger: 'blur' }
  ],
  target_address: [{
  validator: (_r: any, _v: any, cb: (e?: Error) => void) => {
    const addr = (form.value.target_address || '').trim()
    const v = (form.value as any).target_port
    const portEmpty = (v == null || v === '' || Number(v) === 0)

    // 固定目标：必须有地址
    if (requireTarget.value) {
      if (!addr) return cb(new Error('请输入目标地址'))
      return cb()
    }

    // 动态目标：允许两者都空
    if (!addr && portEmpty) return cb()

    // 填了端口但没地址 → 不通过
    if (!addr && !portEmpty) return cb(new Error('已填端口时需填写目标地址'))

    // 其它情况（有地址，端口是否填由 target_port 校验）→ 先通过
    return cb()
  },
  trigger: ['blur', 'change', 'input']
}],
target_port: [{
  validator: (_r: any, v: any, cb: (e?: Error) => void) => {
    const addr = (form.value.target_address || '').trim()
    const portEmpty = (v == null || v === '' || Number(v) === 0)

    // 固定目标：端口必填且 1~65535
    if (requireTarget.value) {
      const n = Number(v)
      if (!Number.isInteger(n) || n < 1 || n > 65535) {
        return cb(new Error('请输入 1~65535 的目标端口'))
      }
      return cb()
    }

    // 动态目标：允许两者都空
    if (!addr && portEmpty) return cb()

    // 有地址则需合法端口
    if (addr) {
      const n = Number(v)
      if (!Number.isInteger(n) || n < 1 || n > 65535) {
        return cb(new Error('请输入 1~65535 的目标端口'))
      }
      return cb()
    }

    // 没地址但给了端口 → 不通过
    if (!addr && !portEmpty) return cb(new Error('已填端口时需填写目标地址'))

    return cb()
  },
  trigger: ['blur', 'change', 'input']
}],
  user_id: [{ required: true, message: '请选择绑定用户', trigger: 'change' }],

  // 限速
  up_limit: [{
    validator: (_r: any, _v: any, cb: (e?:Error)=>void) => {
      if (upVal.value === '') return cb()
      const n = Number(upVal.value)
      if (!Number.isFinite(n) || n < 0) return cb(new Error('上行限速应为 ≥0'))
      cb()
    }, trigger: ['blur','change','input']
  }],
  down_limit: [{
    validator: (_r: any, _v: any, cb: (e?:Error)=>void) => {
      if (downVal.value === '') return cb()
      const n = Number(downVal.value)
      if (!Number.isFinite(n) || n < 0) return cb(new Error('下行限速应为 ≥0'))
      cb()
    }, trigger: ['blur','change','input']
  }],

  // 连接/超时
  max_connection: [{
    validator: (_r: any, v: any, cb: (e?:Error)=>void) => {
      if (v === '' || v == null) return cb()
      const n = Number(v); if (!Number.isInteger(n) || n < 0) return cb(new Error('最大连接应为 ≥0 的整数（0=不限制）'))
      cb()
    }, trigger: 'blur'
  }],
  conn_timeout: [{
    validator: (_r: any, v: any, cb: (e?:Error)=>void) => {
      if (v === '' || v == null) return cb()
      const n = Number(v); if (!Number.isInteger(n) || n < 0) return cb(new Error('连接超时应为 ≥0 ms（0=不限制）'))
      cb()
    }, trigger: 'blur'
  }],
  read_timeout: [{
    validator: (_r: any, v: any, cb: (e?:Error)=>void) => {
      if (v === '' || v == null) return cb()
      const n = Number(v); if (!Number.isInteger(n) || n < 0) return cb(new Error('读超时应为 ≥0 ms（0=不限制）'))
      cb()
    }, trigger: 'blur'
  }],
  write_timeout: [{
    validator: (_r: any, v: any, cb: (e?:Error)=>void) => {
      if (v === '' || v == null) return cb()
      const n = Number(v); if (!Number.isInteger(n) || n < 0) return cb(new Error('写超时应为 ≥0 ms（0=不限制）'))
      cb()
    }, trigger: 'blur'
  }],

  status: [{ required: true, message: '请选择状态', trigger: 'change' }],

  // TLS 证书/私钥：仅 tls-* 协议时必填
  TLSCert: [{
    validator: (_r: any, v: string, cb: (e?:Error)=>void) => {
      if (!needTLSCertKey.value) return cb()
      if (!v || !v.trim()) return cb(new Error('tls-* 协议必须提供证书'))
      cb()
    },
    trigger: ['blur','change','input']
  }],
  TLSKey: [{
    validator: (_r: any, v: string, cb: (e?:Error)=>void) => {
      if (!needTLSCertKey.value) return cb()
      if (!v || !v.trim()) return cb(new Error('tls-* 协议必须提供私钥'))
      cb()
    },
    trigger: ['blur','change','input']
  }],
})

/* 协议切换时，刷新 TLS 字段校验态 */
watch(() => form.value.protocol, async () => {
  if (needTLSCertKey.value) {
    await nextTick()
    formRef.value?.validateField(['TLSCert','TLSKey'])
  } else {
    formRef.value?.clearValidate(['TLSCert','TLSKey'])
  }
})

/* ===================== 数据加载 ===================== */
async function load() {
  const params:any = {page: page.value, size: size.value }

  if (qRuleName.value.trim() !== '') params.rule_name = qRuleName.value.trim()
  if (qProtocol.value) params.protocol = qProtocol.value
  if (qAddr.value.trim() !== '') params.address = qAddr.value.trim()
  if (qPort.value !== '' && qPort.value != null) params.port = Number(qPort.value)

  if (qTAddr.value.trim() !== '') params.target_address = qTAddr.value.trim()
  if (qTPort.value !== '' && qTPort.value != null) params.target_port = Number(qTPort.value)

  if (qUsername.value.trim() !== '') params.username = qUsername.value.trim()
  if (qStatus.value) params.status = qStatus.value

  const { data } = await api.get('/rule', { params })
  list.value = data.list || []
  total.value = Number(data.total || 0)
}
async function loadUser() {
  const { data } = await api.get('/user', { params: { page: 1, size: 1000 } })
  user.value = (data.list || []).map((u: any) => ({ id: Number(u.id), username: String(u.username) }))
}

/* ===================== diff 快照 ===================== */
const original = ref<any>(null)

/* ===================== 规范化 ===================== */
function nOrU(v:any){ return (v===undefined || v===null || v==='') ? undefined : Number(v) }
function normalizeForPayload(src: Rule) {
  const o: any = {}
  o.protocol = normalizeProtocol(src.protocol)
  o.address  = String(src.address || '')
  o.port     = nOrU(src.port)
  o.status   = String(src.status)

  // 新增：rule_name / interface_name（仅 all/tcp/udp 才包含 interface_name）
  const rn = ((src as any).rule_name ?? '').toString().trim()
  if (rn) o.rule_name = rn
  const nowProto = String(o.protocol).toLowerCase()
  const allowIface = nowProto==='all'||nowProto==='tcp'||nowProto==='udp'
  const iface = ((src as any).interface_name ?? '').toString().trim()
  if (allowIface && iface) o.interface_name = iface

  // 目标
  const addr = (src.target_address || '').trim()
  const tport = nOrU(src.target_port)
  const isProxyProt = proxyProtocols.includes(String(o.protocol).toLowerCase())
  if (!(isProxyProt && !addr && (tport === undefined || tport === 0))) {
    if (addr) o.target_address = addr
    if (tport !== undefined) o.target_port = tport
  }

  // 高级（仅固定目标时才纳入；动态目标会在 submit 中按需“清空”主动下发）
  const isHttpOrSocks = ['http/s','tls-http/s','socks5','tls-socks5'].includes(String(o.protocol).toLowerCase())
  const advancedOK = isHttpOrSocks && !!addr && (tport ?? 0) > 0
  if (advancedOK) {
    const au = (src.auth_username || '').trim()
    const ap = (src.auth_password || '').trim()
    if (au !== '') o.auth_username = au
    if (ap !== '') o.auth_password = ap
    if (src.skip_cert_verify) o.skip_cert_verify = true
    const alpn = (src.alpn || '').trim(); if (alpn) o.alpn = alpn
    const fp = (src.tls_fingerprint || '').trim(); if (fp) o.tls_fingerprint = fp
  }

  // TLS：仅在 TLS 协议时携带（SNI 也只在此时包含）
  const tlsCert = (src.TLSCert || src.tls_cert || '').trim()
  const tlsKey  = (src.TLSKey  || src.tls_key  || '').trim()
  const sni     = (src.TLSSNIGuard || src.tls_sni_guard || '').trim()
  const need = ['tls-http/s','tls-socks5','tls-tcp'].includes(String(o.protocol).toLowerCase())
  if (need) {
    if (tlsCert !== '') o.tls_cert = tlsCert
    if (tlsKey  !== '') o.tls_key  = tlsKey
    if (sni     !== '') o.tls_sni_guard = sni
  }

  // SOCKS5
  const isSocks = ['socks5','tls-socks5'].includes(String(o.protocol).toLowerCase())
  if (isSocks) {
    const u = nOrU(src.Socks5UDPPort); const b = nOrU(src.Socks5BindPort)
    if (u !== undefined) o.socks5_udp_port = u
    if (b !== undefined) o.socks5_bind_port = b
  }

  // 限速（UI -> Bytes/s）
  if (upVal.value !== '') {
    const bps = speedToBps(Number(upVal.value), upUnit.value)
    o.up_limit = Math.max(0, Math.floor(bps/8))     // 0 明确表示“不限制”
  }
  if (downVal.value !== '') {
    const bps = speedToBps(Number(downVal.value), downUnit.value)
    o.down_limit = Math.max(0, Math.floor(bps/8))
  }

  // 连接/超时
  const mc = nOrU(src.max_connection); if (mc !== undefined) o.max_connection = mc
  const ct = nOrU(src.conn_timeout);   if (ct !== undefined) o.conn_timeout   = ct
  const rt = nOrU(src.read_timeout);   if (rt !== undefined) o.read_timeout   = rt
  const wt = nOrU(src.write_timeout);  if (wt !== undefined) o.write_timeout  = wt

  // 用户
  const uid = nOrU(src.user_id ?? (src as any).UserID); if (uid !== undefined) o.user_id = uid

  return o
}

/* ===================== 浅 diff（确保单位变化也能被识别） ===================== */
function diffPayload(newObj: any, oldObj: any) {
  const out: any = {}
  const keys = new Set([...Object.keys(newObj), ...Object.keys(oldObj || {})])
  keys.forEach(k => {
    const nv = newObj[k]
    const ov = oldObj?.[k]
    const a = nv === undefined || nv === null ? '' : (typeof nv === 'number' ? String(nv) : String(nv))
    const b = ov === undefined || ov === null ? '' : (typeof ov === 'number' ? String(ov) : String(ov))
    if (a !== b) out[k] = newObj[k]
  })
  return out
}

/* ===================== 打开弹窗 ===================== */
function openCreate() {
  isEdit.value = false
  form.value = {
    id: 0, protocol: 'all', address: '0.0.0.0', port: undefined as any,
    target_address: '', target_port: undefined as any,

    // 新增：默认空串
    rule_name: '',
    interface_name: '',

    up_limit: null, down_limit: null, status: 'enabled',
    max_connection: '', conn_timeout: '', read_timeout: '', write_timeout: '',
    user_id: undefined,

    auth_username: '', auth_password: '', skip_cert_verify: false,
    alpn: '', tls_fingerprint: '',
    TLSCert: '', TLSKey: '', TLSSNIGuard: '',
    Socks5UDPPort: '', Socks5BindPort: '',
    UserID: undefined,
  } as any
  upVal.value = ''; upUnit.value = 'Mbps'
  downVal.value = ''; downUnit.value = 'Mbps'
  original.value = null
  originalHadFixedTarget.value = false
  dialog.value = true
}

function openEdit(r: Rule) {
  isEdit.value = true

  const toDisplay = (v:any)=> (v==null || v===0 ? '' : v)

  const tPort = (r.target_port && r.target_port > 0) ? r.target_port : undefined

  const tlsCert = r.TLSCert ?? r.tls_cert ?? ''
  const tlsKey  = r.TLSKey  ?? r.tls_key  ?? ''
  const sni     = r.TLSSNIGuard ?? r.tls_sni_guard ?? ''
  const uport   = (r.Socks5UDPPort ?? r.socks5_udp_port ?? null) as number | null
  const bport   = (r.Socks5BindPort ?? r.socks5_bind_port ?? null) as number | null

  const authUser = (r as any).auth_username ?? (r as any).AuthUsername ?? ''
  const authPass = (r as any).auth_password ?? (r as any).AuthPassword ?? ''
  const skipCert = (r as any).skip_cert_verify ?? (r as any).SkipCertVerify ?? false
  const alpn     = (r as any).alpn ?? (r as any).ALPN ?? ''
  const fp       = (r as any).tls_fingerprint ?? (r as any).TLSFingerprint ?? ''

  form.value = {
    ...r,
    protocol: normalizeProtocol(r.protocol),
    port: r.port || undefined,
    target_address: r.target_address || '',
    target_port: tPort,

    // 新增：回显
    rule_name: (r as any).rule_name ?? '',
    interface_name: (r as any).interface_name ?? '',

    TLSCert: tlsCert,
    TLSKey: tlsKey,
    TLSSNIGuard: sni,
    Socks5UDPPort: toDisplay(uport),
    Socks5BindPort: toDisplay(bport),
    auth_username: authUser,
    auth_password: authPass,
    skip_cert_verify: Boolean(skipCert),
    alpn: alpn,
    tls_fingerprint: fp,
    max_connection: toDisplay(r.max_connection),
    conn_timeout:   toDisplay(r.conn_timeout),
    read_timeout:   toDisplay(r.read_timeout),
    write_timeout:  toDisplay(r.write_timeout),
    UserID: (r.user_id ?? undefined) as any,
  }

  // 回显限速（Bytes/s -> bps -> 自适应单位）
  if (r.up_limit != null) {
    if (r.up_limit <= 0) { upVal.value = ''; upUnit.value = 'Mbps' }
    else { const { value, unit } = bpsToBestUnitNoBps(Number(r.up_limit)*8); upVal.value = String(value); upUnit.value = unit }
  } else { upVal.value = ''; upUnit.value = 'Mbps' }

  if (r.down_limit != null) {
    if (r.down_limit <= 0) { downVal.value = ''; downUnit.value = 'Mbps' }
    else { const { value, unit } = bpsToBestUnitNoBps(Number(r.down_limit)*8); downVal.value = String(value); downUnit.value = unit }
  } else { downVal.value = ''; downUnit.value = 'Mbps' }

  // 快照（注意：使用当前 upVal/downVal 计算）
  original.value = normalizeForPayload(form.value)

  // 记录是否原本为固定目标
  originalHadFixedTarget.value = !!((r.target_address||'').trim()) && !!(Number(r.target_port||0) > 0)

  dialog.value = true
}

// 生成证书（host = 当前浏览器域名）
async function handleGenerateTLS() {
  const host = window.location.hostname || 'localhost'
  const { data } = await api.get('/tls/generate', {
    params: { host },
  })

  form.value.TLSCert = data.cert || ''
  form.value.TLSKey = data.key || ''
  form.value.TLSSNIGuard = host
  ElMessage.success('TLS 证书已生成')
}

// 从后端配置里取证书
async function handleLoadTLSFromConfig() {
  const { data } = await api.get('/tls/config')

  form.value.TLSCert = data.cert || ''
  form.value.TLSKey = data.key || ''
  form.value.TLSSNIGuard = data.sni_guard || ''
  ElMessage.success('已加载配置中的证书')
}

/* ===================== 保存 ===================== */
async function submit() {
  const ok = await formRef.value?.validate()
  if (!ok) return

  // —— 非 TLS 协议但 TLS 相关有值：保存前确认清空（证书/私钥/SNI） —— //
  let clearTLSOnSave = false
  if (!needTLSCertKey.value) {
    const hasTLSInput =
      !!(form.value.TLSCert?.trim() || form.value.TLSKey?.trim() || form.value.TLSSNIGuard?.trim())
    if (hasTLSInput) {
      try {
        await ElMessageBox.confirm(
          '当前选择的是非 TLS 协议，保存将清空 TLS 证书、私钥与 SNI 白名单。是否继续？',
          '确认清空 TLS 配置',
          { type: 'warning', confirmButtonText: '继续保存并清空', cancelButtonText: '取消' }
        )
        clearTLSOnSave = true
      } catch { return }
    }
  }

  const normalized = normalizeForPayload(form.value)
  if (normalized.user_id == null) { ElMessage.error('请先选择绑定用户'); return }

  // —— 固定目标 → 动态目标 时，提示并清空“可选高级项” —— //
  const nowAddr = (form.value.target_address || '').trim()
  const nowPort = Number((form.value.target_port as any) || 0)
  const nowDynamic = !requireTarget.value && !nowAddr && !(nowPort > 0)
  const isHttpOrSocks = ['http/s','tls-http/s','socks5','tls-socks5'].includes(String(normalized.protocol).toLowerCase())
  if (isEdit.value && originalHadFixedTarget.value && nowDynamic && isHttpOrSocks) {
    try{
      await ElMessageBox.confirm(
        '你正从“固定目标地址”切换为“动态目的地址”。将清空以下高级选项：\n' +
        '• 用户名(auth_username)\n• 密码(auth_password)\n• 跳过证书校验(skip_cert_verify)\n• ALPN(alpn)\n• TLS 指纹(tls_fingerprint)\n' +
        '（仅清空这些可选项；TLS 证书/私钥保持不变）',
        '切换为动态目的地址',
        { type:'warning', confirmButtonText:'继续并清空', cancelButtonText:'取消' }
      )
    }catch{ return }

    normalized.target_address = ''
    normalized.target_port = 0
    normalized.auth_username = ''
    normalized.auth_password = ''
    normalized.skip_cert_verify = false
    normalized.alpn = ''
    normalized.tls_fingerprint = ''
  }

  // 用户确认后，显式清空后端的 TLS（协议不是 tls-* 时）
  if (clearTLSOnSave) {
    normalized.tls_cert = ''
    normalized.tls_key  = ''
    normalized.tls_sni_guard = ''
  }

  // ========= 编辑模式下，非必填项被清空时显式覆盖为空（含新字段） =========
  if (isEdit.value) {
    const had = (k: string) => original.value?.[k] !== undefined
    const nowEmptyStr = (v: any) => v == null || String(v).trim() === ''

    // 1) rule_name：清空 → ''
    if (nowEmptyStr((form.value as any).rule_name) && had('rule_name')) {
      normalized.rule_name = ''
    }

    // 2) interface_name：仅 all/tcp/udp 才允许；若不在其内或已清空且旧值存在 → ''
    const allowIfaceNow = ['all','tcp','udp'].includes(String(normalized.protocol).toLowerCase())
    const ifaceNowEmpty = nowEmptyStr((form.value as any).interface_name)
    if ((!allowIfaceNow || ifaceNowEmpty) && had('interface_name')) {
      normalized.interface_name = ''
    }

    // 3) 目标地址/端口：从有值→空，显式清空
    if (nowEmptyStr(form.value.target_address) && had('target_address')) normalized.target_address = ''
    const tpEmpty = (form.value as any).target_port == null || (form.value as any).target_port === '' || Number((form.value as any).target_port) === 0
    if (tpEmpty && had('target_port')) normalized.target_port = 0

    // 4) 高级可选项清空
    if (nowEmptyStr(form.value.auth_username) && had('auth_username')) normalized.auth_username = ''
    if (nowEmptyStr(form.value.auth_password) && had('auth_password')) normalized.auth_password = ''
    if (had('skip_cert_verify') && !form.value.skip_cert_verify) normalized.skip_cert_verify = false
    if (nowEmptyStr(form.value.alpn) && had('alpn')) normalized.alpn = ''
    if (nowEmptyStr(form.value.tls_fingerprint) && had('tls_fingerprint')) normalized.tls_fingerprint = ''

    // 5) TLS（仍处 TLS 协议）
    const nowTLS = ['tls-http/s','tls-socks5','tls-tcp'].includes(String(form.value.protocol).toLowerCase())
    if (nowTLS) {
      if (nowEmptyStr(form.value.TLSCert) && had('tls_cert')) normalized.tls_cert = ''
      if (nowEmptyStr(form.value.TLSKey)  && had('tls_key'))  normalized.tls_key  = ''
      if (nowEmptyStr(form.value.TLSSNIGuard) && had('tls_sni_guard')) normalized.tls_sni_guard = ''
    }

    // 6) 数值项被清空 -> 0
    const zeroIfCleared = (key: 'max_connection'|'conn_timeout'|'read_timeout'|'write_timeout')=>{
      if ((form.value as any)[key] === '' && (original.value?.[key] !== undefined)) {
        (normalized as any)[key] = 0
      }
    }
    zeroIfCleared('max_connection')
    zeroIfCleared('conn_timeout')
    zeroIfCleared('read_timeout')
    zeroIfCleared('write_timeout')

    // 限速：清空 -> 0（不限制）
    if (upVal.value   === '' && original.value?.up_limit   != null) normalized.up_limit   = 0
    if (downVal.value === '' && original.value?.down_limit != null) normalized.down_limit = 0

    // SOCKS5 两端口：清空 -> 0
    if ((form.value as any).Socks5UDPPort === ''   && (original.value?.socks5_udp_port !== undefined))  normalized.socks5_udp_port  = 0
    if ((form.value as any).Socks5BindPort === ''  && (original.value?.socks5_bind_port !== undefined)) normalized.socks5_bind_port = 0
  }
  // =========================================================================

  // 保存
  if (isEdit.value) {
    const diff = diffPayload(normalized, original.value || {})
    if (Object.keys(diff).length === 0) { ElMessage.info('无任何改动，无需保存'); return }
    await api.put('/rule/' + form.value.id, diff)
    ElMessage.success('保存成功')
  } else {
    const r = await api.post('/rule', normalized)
    if (r?.data?.id) form.value.id = r.data.id
    ElMessage.success('创建成功')
  }
  dialog.value = false
  load()
}


/* ===================== 删除/分页 ===================== */
async function delRow(id: number) { await api.delete('/rule/' + id); ElMessage.success('已删除'); load() }
async function confirmDel(id: number) {
  try {
    await ElMessageBox.confirm('确定删除该规则？此操作不可恢复。','删除确认',
      { type:'warning', confirmButtonText:'删除', cancelButtonText:'取消', autofocus:false, closeOnPressEscape:false, closeOnClickModal:false })
    await delRow(id)
  } catch {}
}
function onPageChange(p:number){ page.value = p; load() }

onMounted(()=>{ load(); loadUser() })
</script>

<template>
  <el-card class="rule-card">
    <template #header>
      <div class="toolbar">
         <!-- 规则名 -->
    <el-input v-model="qRuleName" clearable placeholder="规则名" style="width:160px" />

    <!-- 协议 -->
    <el-select v-model="qProtocol" placeholder="协议" clearable style="width:150px">
      <el-option v-for="o in PROTOCOL_OPTIONS" :key="o.value" :label="o.label" :value="o.value" />
    </el-select>

    <!-- 监听：地址/端口 -->
    <el-input v-model="qAddr" clearable placeholder="监听地址" style="width:170px" />
    <el-input v-model.number="qPort" type="number" inputmode="numeric" clearable placeholder="监听端口" style="width:140px" />

    <!-- 目标：地址/端口 -->
    <el-input v-model="qTAddr" clearable placeholder="目标地址" style="width:170px" />
    <el-input v-model.number="qTPort" type="number" inputmode="numeric" clearable placeholder="目标端口" style="width:140px" />

    <!-- 绑定用户（用户名） -->
    <el-input v-model="qUsername" clearable placeholder="绑定用户" style="width:150px" />

    <!-- 状态 -->
    <el-select v-model="qStatus" placeholder="状态" clearable style="width:120px">
      <el-option label="启用" value="enabled" />
      <el-option label="禁用" value="disabled" />
    </el-select>
        <div class="toolbar__btns">
          <el-button type="primary" @click="load">搜索</el-button>
          <el-button @click="openCreate"  v-if="isAdmin">新增</el-button>
        </div>
      </div>
    </template>

    <div class="table-scroll">
      <el-table :data="list" stripe class="rule-table">
        <el-table-column prop="id" label="ID" width="70" />

        <!-- 新增：规则名 -->
        <el-table-column prop="rule_name" label="规则名" min-width="140">
          <template #default="{ row }">
            {{ (row as any).rule_name ? (row as any).rule_name : '—' }}
          </template>
        </el-table-column>

        <el-table-column prop="protocol" label="协议" width="110" />
        <el-table-column label="监听" min-width="180">
          <template #default="{ row }">{{ row.address }}:{{ row.port }}</template>
        </el-table-column>

        <!-- 新增：接口名（仅 all/tcp/udp 显示值） -->
        <el-table-column label="接口" min-width="120">
          <template #default="{ row }">
            <span v-if="['all','tcp','udp'].includes(String(row.protocol).toLowerCase())">
              {{ (row as any).interface_name || '—' }}
            </span>
            <span v-else>—</span>
          </template>
        </el-table-column>

        <el-table-column label="目标" min-width="220">
          <template #default="{ row }">
            <span v-if="row.target_address && row.target_port">{{ row.target_address }}:{{ row.target_port }}</span>
            <span v-else class="text-muted">（按协议可留空）</span>
          </template>
        </el-table-column>

        <el-table-column label="SOCKS5 端口" min-width="200">
          <template #default="{ row }">
            <span>
              UDP:
              {{
                ((row.socks5_udp_port ?? row.Socks5UDPPort ?? 0) > 0)
                  ? (row.socks5_udp_port ?? row.Socks5UDPPort)
                  : '—'
              }}
            </span>
            <span style="margin:0 6px;">/</span>
            <span>
              BIND:
              {{
                ((row.socks5_bind_port ?? row.Socks5BindPort ?? 0) > 0)
                  ? (row.socks5_bind_port ?? row.Socks5BindPort)
                  : '—'
              }}
            </span>
          </template>
        </el-table-column>

        <el-table-column label="TLS 概览" min-width="220">
          <template #default="{ row }">
            <span v-if="(row.tls_cert || row.TLSCert) || (row.tls_key || row.TLSKey)">
              证:{{ (row.tls_cert || row.TLSCert) ? '√' : '×' }}，
              私:{{ (row.tls_key || row.TLSKey) ? '√' : '×' }}，
              SNI:{{ (row.tls_sni_guard || row.TLSSNIGuard) ? (String(row.tls_sni_guard || row.TLSSNIGuard).split(',').length) : 0 }}
            </span>
            <span v-else class="text-muted">—</span>
          </template>
        </el-table-column>

        <el-table-column label="上/下限（Kbps+）" min-width="240">
          <template #default="{ row }">
            <span>
              ↑ {{ bytesPerSecToBpsLabelDisplay(row.up_limit) }}　
              ↓ {{ bytesPerSecToBpsLabelDisplay(row.down_limit) }}
            </span>
          </template>
        </el-table-column>

        <el-table-column prop="max_connection" label="最大连接" width="110">
          <template #default="{ row }">
            {{ row.max_connection == null ? '—' : (Number(row.max_connection) === 0 ? '不限制' : row.max_connection) }}
          </template>
        </el-table-column>
        <el-table-column prop="conn_timeout" label="连接超时(ms)" width="130">
          <template #default="{ row }">
            {{ row.conn_timeout == null ? '—' : (Number(row.conn_timeout) === 0 ? '不限制' : row.conn_timeout) }}
          </template>
        </el-table-column>
        <el-table-column prop="read_timeout" label="读超时(ms)" width="120">
          <template #default="{ row }">
            {{ row.read_timeout == null ? '—' : (Number(row.read_timeout) === 0 ? '不限制' : row.read_timeout) }}
          </template>
        </el-table-column>
        <el-table-column prop="write_timeout" label="写超时(ms)" width="120">
          <template #default="{ row }">
            {{ row.write_timeout == null ? '—' : (Number(row.write_timeout) === 0 ? '不限制' : row.write_timeout) }}
          </template>
        </el-table-column>

        <el-table-column label="绑定用户" min-width="140">
          <template #default="{ row }">
            <el-tag v-if="row.username" type="info">{{ row.username }}</el-tag>
            <span v-else style="color:#999;">未绑定</span>
          </template>
        </el-table-column>

        <el-table-column label="状态" width="110">
          <template #default="{ row }">
            <el-tag type="success" v-if="row.status === 'enabled'">启用</el-tag>
            <el-tag type="info" v-else>禁用</el-tag>
          </template>
        </el-table-column>

        <el-table-column label="操作" width="200" fixed="right"  v-if="isAdmin">
          <template #default="{ row }">
            <el-button size="small" @click="openEdit(row)">修改</el-button>
            <el-button size="small" type="danger" @click="confirmDel(row.id)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <div class="pager">
      <el-pagination
        background
        layout="prev, pager, next, ->, total"
        :page-size="size"
        :current-page="page"
        :total="total"
        @current-change="onPageChange"
      />
    </div>
  </el-card>

  <el-dialog
    v-model="dialog"
    :title="isEdit ? '编辑规则' : '新增规则'"
    :fullscreen="isSmallScreen"
    width="980px"
    class="rule-dialog"
    destroy-on-close
  >
    <el-form ref="formRef" :model="form" :rules="rulesDef" label-width="150" class="rule-form">

      <el-form-item label="ID" v-if="isEdit"><el-input v-model.number="form.id" disabled /></el-form-item>

      <el-form-item label="协议" prop="protocol">
        <el-select
          v-model="form.protocol"
          placeholder="请选择协议"
          class="protocol-select"
          :teleported="true"
          popper-class="protocol-popper"
        >
          <el-option v-for="o in PROTOCOL_OPTIONS" :key="o.value" :label="o.label" :value="o.value" />
        </el-select>
      </el-form-item>

      <!-- 新增：规则名（可选） -->
      <el-form-item label="规则名">
        <el-input v-model="(form as any).rule_name" clearable class="w-260" placeholder="便于识别" />
      </el-form-item>

      <!-- 监听地址/端口 -->
      <el-form-item label="监听地址/端口">
        <el-row :gutter="8" style="width:100%;">
          <el-col :span="16" :xs="24">
            <el-form-item prop="address" label-width="0" style="margin-bottom:0;">
              <el-input v-model="form.address" clearable placeholder="监听地址" />
            </el-form-item>
          </el-col>
          <el-col :span="8" :xs="24">
            <el-form-item prop="port" label-width="0" style="margin-bottom:0;">
              <el-input v-model.number="form.port" type="number" inputmode="numeric" clearable placeholder="端口（1~65535）" />
            </el-form-item>
          </el-col>
        </el-row>
      </el-form-item>

      <!-- 新增：接口名（仅 all/tcp/udp；提示 NAT 级别） -->
      <el-form-item v-if="showInterfaceName" label="接口名">
        <el-input v-model="(form as any).interface_name" clearable class="w-260" placeholder="如 eth0、ens18" />
        <span class="text-muted ml-8">🥧NAT 级别；只保留总配额判断和流量记录(apt install conntrack)</span>
      </el-form-item>

      <!-- 目标地址/端口（支持一键清空 -> 动态目的地址） -->
      <el-form-item label="目标地址/端口">
        <el-row :gutter="8" style="width:100%;">
          <el-col :span="16" :xs="24">
            <el-form-item prop="target_address" label-width="0" style="margin-bottom:0;">
              <el-input
                v-model="form.target_address"
                clearable
                :placeholder="requireTarget ? '目标地址' : '可留空：动态目的地址'"
                @clear="formRef?.clearValidate('target_address')"
              />
            </el-form-item>
          </el-col>

          <el-col :span="8" :xs="24">
            <el-form-item prop="target_port" label-width="0" style="margin-bottom:0;">
              <!-- 不加 .number，清空才会是 '' -->
              <el-input
                v-model="(form as any).target_port"
                type="number"
                inputmode="numeric"
                clearable
                :placeholder="requireTarget ? '端口（1~65535）' : '可留空/1~65535'"
                @clear="(form as any).target_port=''; formRef?.clearValidate('target_port')"
              />
            </el-form-item>
          </el-col>
        </el-row>
      </el-form-item>

      <!-- 可选高级项 -->
      <el-divider v-if="showAdvancedOpts" content-position="left">可选高级项</el-divider>

      <template v-if="showAdvancedOpts">
<el-form-item label="用户名">
  <el-input
    v-model="form.auth_username"
    class="w-260"
    clearable
    placeholder="auth_username"
    autocomplete="off"
    autocapitalize="off"
    autocorrect="off"
    spellcheck="false"
    :name="`au_${antiFillKey}`"
  />
</el-form-item>

        <el-form-item label="密码">
  <el-input
    v-model="form.auth_password"
    class="w-260"
    type="password"
    clearable
    show-password
    placeholder="auth_password"
    autocomplete="new-password"
    autocapitalize="off"
    autocorrect="off"
    spellcheck="false"
    :name="`ap_${antiFillKey}`"
  />
</el-form-item>

        <el-form-item label="跳过证书校验">
          <el-switch v-model="form.skip_cert_verify" />
        </el-form-item>
        <el-form-item label="ALPN">
          <el-input v-model="form.alpn" class="w-360" clearable placeholder="h2,http/1.1 等；可留空" />
          <span class="text-muted ml-8">🥧</span>
        </el-form-item>
        <el-form-item label="TLS 指纹">
          <el-input v-model="form.tls_fingerprint" class="w-360" clearable placeholder="uTLS 指纹标识；可留空" />
          <span class="text-muted ml-8">🥧</span>
        </el-form-item>
        <el-divider class="adv-end-divider" />
      </template>

      <!-- TLS -->
      <el-form-item v-if="needTLSCertKey" label="TLS 证书" prop="TLSCert">
        <el-input v-model="form.TLSCert" type="textarea" :autosize="{ minRows: 3, maxRows: 12 }" placeholder="粘贴 PEM 或证书路径（必填：tls-* 协议）" />
         <!-- 按钮区域 -->
  <div class="tls-tools" style="margin-top: 8px;">
    <el-button
      size="small"
      type="primary"
      @click="handleGenerateTLS"
    >
      生成证书（当前域名）
    </el-button>
    <el-button
      size="small"
      @click="handleLoadTLSFromConfig"
      style="margin-left: 8px;"
    >
      使用配置中的证书
    </el-button>
  </div>
      </el-form-item>
      <el-form-item v-if="needTLSCertKey" label="TLS 私钥" prop="TLSKey">
        <el-input v-model="form.TLSKey" type="textarea" :autosize="{ minRows: 3, maxRows: 12 }" placeholder="粘贴 PEM 或私钥路径（必填：tls-* 协议）" />
      </el-form-item>
      <el-form-item v-if="isTLSHTTPorSOCKS || isTLSTCP" label="SNI 白名单">
        <el-input v-model="form.TLSSNIGuard" type="textarea" :autosize="{ minRows: 2, maxRows: 10 }" placeholder="example.com,*.foo.com；留空=不限制" />
      </el-form-item>

      <!-- SOCKS5 -->
      <el-form-item v-if="isSocks5Family" label="SOCKS5 UDP 端口" prop="Socks5UDPPort">
        <el-input
          v-model="(form as any).Socks5UDPPort"
          type="number"
          inputmode="numeric"
          clearable
          class="w-220"
          placeholder=""
          @clear="(form as any).Socks5UDPPort=''"
        />
        <span class="text-muted ml-8">🥧UDP 与 BIND 不可相同</span>
      </el-form-item>
      <el-form-item v-if="isSocks5Family" label="SOCKS5 BIND 端口" prop="Socks5BindPort">
        <el-input
          v-model="(form as any).Socks5BindPort"
          type="number"
          inputmode="numeric"
          clearable
          class="w-220"
          placeholder=""
          @clear="(form as any).Socks5BindPort=''"
        />
      </el-form-item>

      <!-- 限速（Kbps+） -->
      <el-form-item label="上行上限" prop="up_limit">
        <div class="row-inline">
          <el-input
            v-model="upVal"
            clearable
            @clear="upVal=''"
            type="number"
            inputmode="decimal"
            class="w-180 mr-8"
            placeholder="留空=不限制"
          />
          <el-select v-model="upUnit" class="w-160" :teleported="true">
            <el-option v-for="u in speedUnits" :key="u" :label="u" :value="u" />
          </el-select>
        </div>
      </el-form-item>

      <el-form-item label="下行上限" prop="down_limit">
        <div class="row-inline">
          <el-input
            v-model="downVal"
            clearable
            @clear="downVal=''"
            type="number"
            inputmode="decimal"
            class="w-180 mr-8"
            placeholder="留空=不限制"
          />
          <el-select v-model="downUnit" class="w-160" :teleported="true">
            <el-option v-for="u in speedUnits" :key="u" :label="u" :value="u" />
          </el-select>
        </div>
      </el-form-item>

      <!-- 连接/超时（可清空） -->
      <el-form-item label="最大连接" prop="max_connection">
        <el-input v-model="(form as any).max_connection" type="number" inputmode="numeric" clearable class="w-160" placeholder="留空/0=不限制" />
      </el-form-item>
      <el-form-item label="连接超时(ms)" prop="conn_timeout">
        <el-input v-model="(form as any).conn_timeout" type="number" inputmode="numeric" clearable class="w-160" placeholder="留空/0=不限制" />
      </el-form-item>
      <el-form-item label="读超时(ms)" prop="read_timeout">
        <el-input v-model="(form as any).read_timeout" type="number" inputmode="numeric" clearable class="w-160" placeholder="留空/0=不限制" />
      </el-form-item>
      <el-form-item label="写超时(ms)" prop="write_timeout">
        <el-input v-model="(form as any).write_timeout" type="number" inputmode="numeric" clearable class="w-160" placeholder="留空/0=不限制" />
      </el-form-item>

      <!-- 绑定用户 -->
      <el-form-item label="绑定用户" prop="user_id">
        <el-select v-model="form.user_id" class="w-260" filterable placeholder="请选择用户" :teleported="true"
                   @change="(v:any)=>{ form.UserID = v }">
          <el-option v-for="u in user" :key="u.id" :label="u.username" :value="u.id" />
        </el-select>
      </el-form-item>

      <el-form-item label="状态" prop="status">
        <el-select v-model="form.status" class="w-220" :teleported="true">
          <el-option value="enabled" label="启用" />
          <el-option value="disabled" label="禁用" />
        </el-select>
      </el-form-item>
    </el-form>

    <template #footer>
      <el-button @click="dialog = false">取消</el-button>
      <el-button type="primary" @click="submit">保存</el-button>
    </template>
  </el-dialog>
</template>

<style scoped>
.text-muted { color: var(--el-text-color-secondary); }
.w-160{ width:160px; } .w-180{ width:180px; } .w-220{ width:220px; } .w-260{ width:260px; } .w-360{ width:360px; }
.mr-8{ margin-right:8px; } .ml-8{ margin-left:8px; }
.row-inline{ display:flex; align-items:center; gap:8px; flex-wrap:wrap; }

.toolbar { display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
.toolbar__input { width: 260px; max-width: 70vw; }
.toolbar__btns  { display:flex; gap:8px; }

.table-scroll { width: 100%; overflow-x: auto; }
.rule-table   { min-width: 1120px; }

.pager { margin-top: 8px; text-align: right; }

.rule-dialog :deep(.el-dialog__body) { max-height: 70vh; overflow:auto; }

.rule-form :deep(.el-select .el-select__selected-item){
  line-height: 22px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.rule-form :deep(.el-select .el-input__wrapper){
  min-height: 36px;
  align-items: center;
  box-sizing: border-box;
}

.protocol-select { width: 100%; }
:deep(.protocol-popper.el-popper){ min-width: 180px; max-width: 90vw; z-index: 3000; }
:deep(.protocol-popper .el-select-dropdown__item){ white-space: nowrap; }

/* 高级项结束分隔线 */
.adv-end-divider { margin-top: -4px; }

@media (max-width: 600px) {
  .toolbar__input { width: 100%; max-width: 100%; }
  .toolbar__btns  { width: 100%; }

  .rule-dialog :deep(.el-dialog__body) { max-height: calc(100vh - 120px); }

  .rule-form :deep(.el-form-item__content) { flex-wrap: wrap; }
  .rule-form :deep(.el-form-item__label)   { width: 110px !important; }

  .w-160, .w-180, .w-220, .w-260, .w-360 { width: 100% !important; }
}
</style>
