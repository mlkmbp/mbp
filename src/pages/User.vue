<!-- src/pages/User.vue -->
<script setup lang="ts">
import { inject, ref, type Ref, onMounted, onBeforeUnmount, computed, watch, nextTick } from 'vue'
import { ElMessage, ElMessageBox, type FormInstance, type FormRules, type FormItemRule } from 'element-plus'
import api from '../api'

const isAdmin = inject<Ref<boolean>>('isAdmin', ref(false))

/* ===================== 容量（十进制 1000 制） ===================== */
type UnitDec = 'B' | 'KB' | 'MB' | 'GB' | 'TB'
const DEC_STEP = 1000

function toBytesDecimal(v: number, unit: UnitDec): number {
  if (!Number.isFinite(v) || v < 0) return 0
  switch (unit) {
    case 'B': return Math.floor(v)
    case 'KB': return Math.floor(v * DEC_STEP)
    case 'MB': return Math.floor(v * DEC_STEP ** 2)
    case 'GB': return Math.floor(v * DEC_STEP ** 3)
    case 'TB': return Math.floor(v * DEC_STEP ** 4)
  }
}
function fromBytesDecimal(bytes: number): { value: number, unit: UnitDec } {
  if (!bytes || bytes < 0) return { value: 0, unit: 'B' }
  const table: [UnitDec, number][] = [
    ['TB', DEC_STEP ** 4],
    ['GB', DEC_STEP ** 3],
    ['MB', DEC_STEP ** 2],
    ['KB', DEC_STEP ** 1],
    ['B', 1],
  ]
  for (const [u, mul] of table) {
    if (bytes >= mul) return { value: +(bytes / mul).toFixed(2), unit: u }
  }
  return { value: bytes, unit: 'B' }
}
function formatDec(bytes: number): string {
  const { value, unit } = fromBytesDecimal(bytes || 0)
  const n = Math.abs(value) >= 100 ? Math.round(value) : +value.toFixed(2)
  return `${n} ${unit}`
}
function formatQuota(bytes: number): string { return !bytes ? '不限' : formatDec(bytes) }

/* ===================== 速率（bits/s，1000 制） <-> 接口 Bytes/s ===================== */
type SpeedUnit = 'Kbps' | 'Mbps' | 'Gbps' | 'Tbps'
const speedUnits: SpeedUnit[] = ['Kbps', 'Mbps', 'Gbps', 'Tbps']

function speedToBytesPerSec(v: number, unit: SpeedUnit): number {
  const K10 = 1000
  if (!Number.isFinite(v) || v <= 0) return 0
  switch (unit) {
    case 'Kbps': return Math.floor((v * K10) / 8)
    case 'Mbps': return Math.floor((v * (K10 ** 2)) / 8)
    case 'Gbps': return Math.floor((v * (K10 ** 3)) / 8)
    case 'Tbps': return Math.floor((v * (K10 ** 4)) / 8)
  }
}
function autoPickSpeedUnitFromBytesPerSec(bytesPerSec?: number | null): { value: number | null, unit: SpeedUnit } {
  if (!bytesPerSec || bytesPerSec <= 0) return { value: null, unit: 'Mbps' }
  const bps = bytesPerSec * 8
  const K10 = 1000
  const table: [SpeedUnit, number][] = [
    ['Tbps', K10 ** 4],
    ['Gbps', K10 ** 3],
    ['Mbps', K10 ** 2],
    ['Kbps', K10 ** 1],
  ]
  for (const [u, mul] of table) {
    if (bps >= mul) return { value: +(bps / mul).toFixed(3), unit: u }
  }
  return { value: 1, unit: 'Kbps' }
}
function bytesPerSecToAutoUnit(bytesPerSec?: number | null): string {
  if (!bytesPerSec || bytesPerSec <= 0) return '-'
  const bps = bytesPerSec * 8
  const K10 = 1000
  if (bps < K10) return '<1 Kbps'
  const table: [SpeedUnit, number][] = [
    ['Tbps', K10 ** 4],
    ['Gbps', K10 ** 3],
    ['Mbps', K10 ** 2],
    ['Kbps', K10 ** 1],
  ]
  for (const [u, mul] of table) {
    if (bps >= mul) {
      const v = bps / mul
      const n = Math.abs(v) >= 100 ? Math.round(v) : +v.toFixed(2)
      return `${n} ${u}`
    }
  }
  return '<1 Kbps'
}

/* ===================== 类型 ===================== */
type PeriodUnit = 'day' | 'month' | ''  // '' 代表未设置
interface User {
  id: number
  vm_id?: number | null
  username: string
  password: string
  quota: number
  up: number
  down: number
  status: 'enabled' | 'disabled' | 'expired'
  start_date_time?: string | null
  expired_date_time?: string | null
  period_unit?: PeriodUnit | null
  period_left?: number | null
  up_limit?: number | null // Bytes/s
  down_limit?: number | null
  create_date_time?: string | null
  update_date_time?: string | null
}

/* ===================== 列表与分页 ===================== */
const username = ref(''); const page = ref(1); const size = ref(10)
const sort = ref('id_desc')
const total = ref(0); const list = ref<User[]>([])

type Op = '' | 'eq' | 'gt' | 'lt' | 'ge' | 'le'
const opOptions: {label:string,value:Op}[] = [
  { label: '=', value: 'eq' },
  { label: '≥', value: 'ge' },
  { label: '≤', value: 'le' },
  { label: '>', value: 'gt' },
  { label: '<', value: 'lt' },
]
const qVmId = ref<string>('')                                // vm_id
const qStatus = ref<'' | 'enabled' | 'disabled' | 'expired'>('')         // status
const qPeriodUnit = ref<PeriodUnit>('')                      // period_unit

// quota（带单位与运算符；发送给后端用 Bytes）
const qQuotaVal = ref<number | ''>('')                       // 数值
const qQuotaUnit = ref<UnitDec>('GB')                        // 单位
const qQuotaOp = ref<Op>('')                                 // 运算符

// start/expired（时间字符串 + 运算符）
const qStart = ref<string | null>(null)
// const qStartOp = ref<Op>('')

const qExpired = ref<string | null>(null)
// const qExpiredOp = ref<Op>('')

// left（剩余周期 + 运算符）
const qLeftVal = ref<number | ''>('')
const qLeftOp = ref<Op>('')

/* ===================== 弹窗/表单 ===================== */
const dialog = ref(false)
const isEdit = ref(false)
const isSmallScreen = ref(typeof window !== 'undefined' ? window.innerWidth <= 600 : false)
function onResize() { isSmallScreen.value = window.innerWidth <= 600 }
onMounted(async () => { window.addEventListener('resize', onResize); await load() })
onBeforeUnmount(() => window.removeEventListener('resize', onResize))

const formRef = ref<FormInstance>()
const form = ref<User>({
  id: 0, vm_id: null, username: '', password: '', quota: 0, up: 0, down: 0,
  status: 'enabled', start_date_time: null, expired_date_time: null,
  period_unit: '', period_left: null, up_limit: null, down_limit: null,
  create_date_time: null, update_date_time: null,
})
const original = ref<User | null>(null)

/* —— 与 rule.vue 一致的输入风格 —— */
const quotaVal = ref<number | ''>(''); const quotaUnit = ref<UnitDec>('GB'); const quotaPicked = ref(false)
const upLimitVal = ref<number | ''>(''); const upLimitUnit = ref<SpeedUnit>('Mbps'); const upPicked = ref(false)
const downLimitVal = ref<number | ''>(''); const downLimitUnit = ref<SpeedUnit>('Mbps'); const downPicked = ref(false)

/* 起止时间选择器：选日补当前时分秒 */
const pad = (n: number) => String(n).padStart(2, '0')
function nowHms() { const d = new Date(); return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}` }

const formStart = ref<string | null>(null)
const startPicked = ref(false)
function onPickStart() {
  startPicked.value = true
  const s = String(formStart.value ?? '')
  if (!s) return
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) formStart.value = `${s} ${nowHms()}`
  else if (/^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}$/.test(s) && s.endsWith('00:00:00')) formStart.value = s.slice(0, 10) + ' ' + nowHms()
}
function onClearStart() { startPicked.value = true; formStart.value = null }

const formExpired = ref<string | null>(null)
const picked = ref(false)
function onPick() {
  picked.value = true
  const s = String(formExpired.value ?? '')
  if (!s) return
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) formExpired.value = `${s} ${nowHms()}`
  else if (/^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}$/.test(s) && s.endsWith('00:00:00')) formExpired.value = s.slice(0, 10) + ' ' + nowHms()
}
function onClear() { picked.value = true; formExpired.value = null }

/* 周期设置（编辑/新增都显示空更好看；用户可手动填 0） */
const periodUnit = ref<PeriodUnit>('')     // '' 不设置
const periodLeftVal = ref<string>('')      // 用字符串承载：''/ '0' / '123'

/* ===================== 校验 ===================== */
const baseRules: FormRules = {
  username: [
    { required: true, message: '请输入用户名', trigger: ['blur', 'change'] },
    { min: 6, max: 64, message: '长度 6-64', trigger: ['blur', 'change'] },
    { validator: (_r, v: string, cb) => ((v ?? '').trim() !== v ? cb(new Error('首尾不能有空格')) : cb()), trigger: ['blur', 'change'] },
  ],
  status: [{ required: true, message: '请选择状态', trigger: 'change' }],
}
type EPValidatorCb = (error?: Error) => void
const passwordRules = computed(() => (
  isEdit.value ? [
    { min: 6, max: 64, message: '长度 6-64', trigger: ['blur', 'change'] },
    { validator: (_r: FormItemRule, v: string, cb: EPValidatorCb) => (v && v.trim() !== v ? cb(new Error('首尾不能有空格')) : cb()), trigger: ['blur', 'change', 'input'] },
  ] : [
    { required: true, message: '请输入密码', trigger: ['blur', 'change'] },
    { min: 6, max: 64, message: '长度 6-64', trigger: ['blur', 'change'] },
    { validator: (_r: FormItemRule, v: string, cb: EPValidatorCb) => (v && v.trim() !== v ? cb(new Error('首尾不能有空格')) : cb()), trigger: ['blur', 'change', 'input'] },
  ]
))

/* ===================== 列表加载 ===================== */
async function load() {
  const params: any = {
    username: username.value,
    page: page.value,
    size: size.value,
    sort: sort.value,
  }

  // 精确 VMID
  if (String(qVmId.value).trim() !== '') params.vm_id = qVmId.value

  // 状态
  if (qStatus.value) params.status = qStatus.value

  // 周期单位
  if (qPeriodUnit.value) params.period_unit = qPeriodUnit.value

  // 配额：带单位 => Bytes；仅在填写数值时发送；运算符可选
  if (qQuotaVal.value !== '') {
    params.quota = toBytesDecimal(Number(qQuotaVal.value), qQuotaUnit.value)
    if (qQuotaOp.value) params.quota_op = qQuotaOp.value
  }

  // 开始时间：仅在选择时发送；运算符可选
  if (qStart.value) {
    params.start = qStart.value
    // if (qStartOp.value) params.start_op = qStartOp.value
     params.start_op = "ge"

  }

  // 过期时间
  if (qExpired.value) {
    params.expired = qExpired.value
    // if (qExpiredOp.value) params.expired_op = qExpiredOp.value
    params.expired_op = "le"
  }

  // 剩余周期
  if (qLeftVal.value !== '') {
    params.left = Number(qLeftVal.value)
    if (qLeftOp.value) params.left_op = qLeftOp.value
  }

  const { data } = await api.get('/user', { params })
  list.value = data.list
  total.value = data.total
}

/* ===================== 规范化 & 比较 ===================== */
// VM: ''/null/undefined/0 -> 0；其它 -> 正整数
const normVm = (v: any) => {
  if (v === '' || v === null || v === undefined) return 0
  const n = Number(v)
  return Number.isFinite(n) ? n : 0
}
// Unit: 'day'/'month' 以外 -> ''
const normUnit = (v: any): PeriodUnit => (v === 'day' || v === 'month') ? v : ''
// Left: ''/null/undefined -> null；其余 -> 整数（可为 0、-1）
const normLeft = (v: any): number | null => {
  if (v === '' || v === null || v === undefined) return null
  const n = Number(v)
  return Number.isFinite(n) ? Math.trunc(n) : null
}
// 中文展示
const unitLabelCN = (u: any) => (u === 'day' ? '天' : u === 'month' ? '月' : '-')

/* ===================== 新增/编辑 ===================== */
function openCreate() {
  isEdit.value = false
  form.value = {
    id: 0, vm_id: null, username: '', password: '', quota: 0, up: 0, down: 0, status: 'enabled',
    start_date_time: null, expired_date_time: null, period_unit: '', period_left: null,
    up_limit: null, down_limit: null, create_date_time: null, update_date_time: null,
  }

  quotaVal.value = ''; quotaUnit.value = 'GB'; quotaPicked.value = false
  upLimitVal.value = ''; upLimitUnit.value = 'Mbps'; upPicked.value = false
  downLimitVal.value = ''; downLimitUnit.value = 'Mbps'; downPicked.value = false

  formStart.value = null; startPicked.value = false
  formExpired.value = null; picked.value = false

  // 新增页：VMID、剩余周期显示 '' 好看
  form.value.vm_id = '' as any
  periodUnit.value = ''
  periodLeftVal.value = ''

  original.value = null
  dialog.value = true
}

function openEdit(r: User) {
  isEdit.value = true
  form.value = JSON.parse(JSON.stringify(r))
  original.value = JSON.parse(JSON.stringify(r))

  // 配额
  if ((r.quota ?? 0) === 0) { quotaVal.value = ''; quotaUnit.value = 'GB' }
  else { const qx = fromBytesDecimal(r.quota || 0); quotaVal.value = qx.value; quotaUnit.value = qx.unit }
  quotaPicked.value = false

  // 限速
  const upPick = autoPickSpeedUnitFromBytesPerSec(r.up_limit ?? null)
  upLimitVal.value = (upPick.value == null) ? '' : upPick.value
  upLimitUnit.value = upPick.unit
  upPicked.value = false
  const downPick = autoPickSpeedUnitFromBytesPerSec(r.down_limit ?? null)
  downLimitVal.value = (downPick.value == null) ? '' : downPick.value
  downLimitUnit.value = downPick.unit
  downPicked.value = false

  // 起止时间
  formStart.value = r.start_date_time ?? null; startPicked.value = false
  formExpired.value = r.expired_date_time ?? null; picked.value = false

  // 编辑页：VMID/剩余周期显示为空串（0/未设 都显示空）
  form.value.vm_id = (r.vm_id && r.vm_id !== 0) ? r.vm_id : ('' as any)
  periodUnit.value = normUnit(r.period_unit)
  periodLeftVal.value = (typeof r.period_left === 'number' && r.period_left !== 0) ? String(r.period_left) : ''

  // 密码回显
  form.value.password = r.password ?? ''

  dialog.value = true
}

/* —— 标记“被操作过” —— */
const onPickQuota = () => (quotaPicked.value = true)
const onClearQuota = () => { quotaPicked.value = true; quotaVal.value = '' }
const onPickUpLimit = () => (upPicked.value = true)
const onClearUpLimit = () => { upPicked.value = true; upLimitVal.value = '' }
const onPickDownLimit = () => (downPicked.value = true)
const onClearDownLimit = () => { downPicked.value = true; downLimitVal.value = '' }

/* ===================== 提交 ===================== */
async function submit() {
  const ok = await formRef.value?.validate()
  if (!ok) return
  if (isEdit.value && !form.value.id) { ElMessage.error('缺少 id，无法修改'); return }

  const payload: any = isEdit.value ? { id: form.value.id } : {}
  const has = (k: string) => Object.prototype.hasOwnProperty.call(payload, k)

  // 用户名/状态
  if (!isEdit.value || form.value.username !== original.value?.username) payload.username = form.value.username
  if (!isEdit.value || form.value.status !== original.value?.status) payload.status = form.value.status

  // 密码
  const p = (form.value.password ?? '').trim()
  if (isEdit.value) {
    const old = (original.value?.password ?? '').trim()
    if (p !== old) {
      if (p.length < 6) { ElMessage.error('新密码长度需 ≥ 6'); return }
      payload.password = p
    }
  } else {
    if (!p || p.length < 6) { ElMessage.error('请输入不少于 6 位的密码'); return }
    payload.password = p
  }

  // VMID: 对比变化；清空 => 0
  const newVm = normVm(form.value.vm_id as any)
  const oldVm = normVm(original.value?.vm_id as any)
  if (!isEdit.value) {
    if (newVm !== 0) payload.vm_id = newVm
  } else if (newVm !== oldVm) {
    payload.vm_id = newVm
  }

  // 配额：被操作过才发
  if (!isEdit.value) {
    payload.quota = quotaPicked.value ? (quotaVal.value === '' ? 0 : toBytesDecimal(Number(quotaVal.value), quotaUnit.value)) : 0
  } else if (quotaPicked.value) {
    payload.quota = (quotaVal.value === '' ? 0 : toBytesDecimal(Number(quotaVal.value), quotaUnit.value))
  }

  // 起始/过期时间：被操作过才发；清空 -> ''
  if (startPicked.value) payload.start_date_time = (formStart.value ? formStart.value : '')
  if (picked.value)      payload.expired_date_time = (formExpired.value ? formExpired.value : '')

  // 周期：支持 unit 清到 ''，left 改到 0；按变化发送
  const newUnit = normUnit(periodUnit.value)
  const oldUnit = normUnit(original.value?.period_unit)
  if (!isEdit.value) {
    if (newUnit !== '') payload.period_unit = newUnit
  } else if (newUnit !== oldUnit) {
    payload.period_unit = newUnit
  }

  const newLeft = normLeft(periodLeftVal.value) // null/number
  const oldLeft = (typeof original.value?.period_left === 'number') ? original.value!.period_left : 0
  if (!isEdit.value) {
    if (newLeft !== null) payload.period_left = newLeft
  } else {
    const newLeftForSend = (newLeft === null ? 0 : newLeft) // 清空 -> 0
    if (newLeftForSend !== oldLeft) payload.period_left = newLeftForSend
  }

  // ===== 关键修正：按“改动后的有效值”校验，不只看这次是否发送 =====
  // 有效周期 = unit != '' 且 left 为 number（含 0、-1）
  const effectiveUnit = has('period_unit') ? normUnit(payload.period_unit) : normUnit(original.value?.period_unit)
  const effectiveLeftRaw = has('period_left') ? payload.period_left : original.value?.period_left
  const effectiveHasLeft = typeof effectiveLeftRaw === 'number' && Number.isFinite(effectiveLeftRaw)

  // 有效起始/过期（优先本次 payload，否则用原值；空串视为无效）
  // const effectiveStart  = has('start_date_time')   ? (payload.start_date_time ?? '')   : (original.value?.start_date_time ?? '')
  const effectiveExpire = has('expired_date_time') ? (payload.expired_date_time ?? '') : (original.value?.expired_date_time ?? '')

  // 规则：
  // 1) 若“有效周期”成立，则 expired 不能为 ''。
  //    - 创建：必须这次显式提供 expired 且非 ''（因为没有原值可依赖）
  //    - 编辑：允许沿用原值，但若本次把 expired 清空为 ''，禁止
  // 2) 若“有效周期”成立，本次若提交了 start 且为 ''，禁止（不允许在有周期时清空 start）
  if (effectiveUnit !== '' && effectiveHasLeft) {
    if (!isEdit.value) {
      // 创建：要求这次必须发 expired 且非空
      if (!has('expired_date_time') || payload.expired_date_time === '') {
        ElMessage.error('设置了周期时，必须同时设置“过期时间”（且不可为空）')
        return
      }
    } else {
      // 编辑：整体有效，但不允许把 expired 清成 ''
      if (has('expired_date_time') && payload.expired_date_time === '') {
        ElMessage.error('有效周期下，过期时间不可清空')
        return
      }
      // 同理，提交了 start 但清空 -> 不允许
      if (has('start_date_time') && payload.start_date_time === '') {
        ElMessage.error('有效周期下，开始时间不可清空（如需清空，请先取消周期设置）')
        return
      }
      // 如果原本和本次都没有有效的 expired（即依然是 ''），也不允许通过
      if (!has('expired_date_time') && effectiveExpire === '') {
        ElMessage.error('有效周期下，过期时间不得为空')
        return
      }
    }
  }

  // 上/下行上限
  if (upPicked.value) payload.up_limit = (upLimitVal.value === '' ? 0 : speedToBytesPerSec(Number(upLimitVal.value), upLimitUnit.value))
  if (downPicked.value) payload.down_limit = (downLimitVal.value === '' ? 0 : speedToBytesPerSec(Number(downLimitVal.value), downLimitUnit.value))

  // period_left 数值校验（仅在将要发送时）
  if (has('period_left')) {
    const v = payload.period_left
    if (!(v === -1 || (Number.isInteger(v) && v >= 0))) {
      ElMessage.error('剩余周期必须为 -1 或者 ≥ 0 的整数')
      return
    }
  }

  if (isEdit.value) { await api.put('/user/' + form.value.id, payload); ElMessage.success('保存成功') }
  else { await api.post('/user', payload); ElMessage.success('创建成功') }

  dialog.value = false
  load()
}


/* ===================== 删除 ===================== */
async function delRow(id: number) { await api.delete('/user/' + id); ElMessage.success('已删除'); load() }
async function confirmDel(id: number) {
  try {
    await ElMessageBox.confirm('确定删除该用户？此操作不可恢复。', '删除确认',
      { type: 'warning', confirmButtonText: '删除', cancelButtonText: '取消', autofocus: false, closeOnPressEscape: false, closeOnClickModal: false })
    await delRow(id)
  } catch { }
}

/* ===================== 其他 ===================== */
function onPageChange(p: number) { page.value = p; load() }

/* ====== 防止浏览器自动填充（用户名/密码） ====== */
const unameName = 'u_' + Math.random().toString(36).slice(2)
const passName = 'p_' + Math.random().toString(36).slice(2)
const usernameReadonly = ref(true)
const passwordReadonly = ref(true)
function resetReadonlyOnOpen() {
  usernameReadonly.value = true
  passwordReadonly.value = true
  nextTick(() => { /* focus 时移除 readonly */ })
}
watch(dialog, v => { if (v) resetReadonlyOnOpen() })
</script>

<template>
  <el-card class="user-card">
    <template #header>
      <div class="toolbar">
         <!-- 原有：用户名 -->
        <el-input v-model="username" placeholder="搜索用户名" class="toolbar__input" @keyup.enter="load" clearable />

        <!-- 新增：VMID（精确） -->
        <el-input v-model="qVmId" placeholder="VMID" style="width:120px" clearable />

        <!-- 新增：状态 -->
        <el-select v-model="qStatus" placeholder="状态" style="width:120px" clearable>
          <el-option label="正常" value="enabled" />
          <el-option label="禁用" value="disabled" />
          <el-option label="过期" value="expired" />
        </el-select>

        <!-- 新增：周期单位 -->
        <el-select v-model="qPeriodUnit" placeholder="周期单位" style="width:120px" clearable>
          <el-option label="天" value="day" />
          <el-option label="月" value="month" />
        </el-select>

        <!-- 新增：配额（运算符 + 数值 + 单位） -->
        <div class="row-compact">
          <el-select v-model="qQuotaOp" placeholder="配额" style="width:80px" clearable>
            <el-option v-for="op in opOptions" :key="op.value" :label="op.label" :value="op.value" />
          </el-select>
          <el-input v-model.number="qQuotaVal" type="number" inputmode="decimal" placeholder="配额数值" style="width:140px" clearable />
          <el-select v-model="qQuotaUnit" style="width:110px">
            <el-option label="B" value="B" />
            <el-option label="KB" value="KB" />
            <el-option label="MB" value="MB" />
            <el-option label="GB" value="GB" />
            <el-option label="TB" value="TB" />
          </el-select>
        </div>

        <!-- 新增：开始时间（运算符 + 时间） -->
        <div class="row-compact">
          <!-- <el-select v-model="qStartOp" placeholder="开始" style="width:80px" clearable>
            <el-option v-for="op in opOptions" :key="op.value" :label="op.label" :value="op.value" />
          </el-select> -->
          <el-date-picker
            v-model="qStart"
            type="datetime"
            placeholder="开始时间"
            format="YYYY-MM-DD HH:mm:ss"
            value-format="YYYY-MM-DD HH:mm:ss"
            :editable="false"
            clearable
            style="width:210px"
          />
        </div>

        <!-- 新增：过期时间（运算符 + 时间） -->
        <div class="row-compact">
          <!-- <el-select v-model="qExpiredOp" placeholder="过期" style="width:80px" clearable>
            <el-option v-for="op in opOptions" :key="op.value" :label="op.label" :value="op.value" />
          </el-select> -->
          <el-date-picker
            v-model="qExpired"
            type="datetime"
            placeholder="过期时间"
            format="YYYY-MM-DD HH:mm:ss"
            value-format="YYYY-MM-DD HH:mm:ss"
            :editable="false"
            clearable
            style="width:210px"
          />
        </div>

        <!-- 新增：剩余周期（运算符 + 数值） -->
        <div class="row-compact">
          <el-select v-model="qLeftOp" placeholder="剩余" style="width:80px" clearable>
            <el-option v-for="op in opOptions" :key="op.value" :label="op.label" :value="op.value" />
          </el-select>
          <el-input v-model="qLeftVal" type="number" inputmode="numeric" placeholder="剩余周期" style="width:140px" clearable />
        </div>

        <!-- 排序：新增 start/expired/quota -->
        <el-select v-model="sort" placeholder="排序" style="width:160px">
          <el-option label="ID ↓" value="id_desc" />
          <el-option label="ID ↑" value="id_asc" />
          <el-option label="已用 ↓" value="used_desc" />
          <el-option label="已用 ↑" value="used_asc" />
          <el-option label="更新时间 ↓" value="update_desc" />
          <el-option label="更新时间 ↑" value="update_asc" />
          <el-option label="开始时间 ↓" value="start_desc" />
          <el-option label="开始时间 ↑" value="start_asc" />
          <el-option label="过期时间 ↓" value="expired_desc" />
          <el-option label="过期时间 ↑" value="expired_asc" />
          <el-option label="配额 ↓" value="quota_desc" />
          <el-option label="配额 ↑" value="quota_asc" />
        </el-select>
        <div class="toolbar__btns">
          <el-button type="primary" @click="load">搜索</el-button>
          <el-button @click="openCreate" v-if="isAdmin">新增</el-button>
        </div>
      </div>
    </template>

    <div class="table-scroll">
      <el-table :data="list" stripe class="user-table">
        <el-table-column prop="id" label="ID" width="80" />
        <el-table-column prop="vm_id" label="VMID" width="120">
  <template #default="{ row }">
    <span v-if="!row.vm_id || row.vm_id === 0" class="muted">-</span>
    <router-link v-else :to="`/pve/${row.vm_id}`" class="vm-link">#{{ row.vm_id }}</router-link>
  </template>
</el-table-column>
        <el-table-column prop="username" label="用户名" min-width="160" />
        <el-table-column prop="password_sha256" label="密码sha256" min-width="180" />
        <el-table-column label="配额" min-width="140">
          <template #default="{ row }">
            <el-tooltip :content="row.quota === 0 ? '不限' : `${row.quota} B`" placement="top">
              <span>{{ formatQuota(row.quota) }}</span>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column label="已用" min-width="140">
          <template #default="{ row }">
            <el-tooltip :content="`${row.up + row.down} B`" placement="top">
              <span>{{ formatDec(row.up + row.down) }}</span>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column label="已上行" min-width="140">
          <template #default="{ row }">
            <el-tooltip :content="`${row.up} B`" placement="top">
              <span>{{ formatDec(row.up) }}</span>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column label="已下行" min-width="140">
          <template #default="{ row }">
            <el-tooltip :content="`${row.down} B`" placement="top">
              <span>{{ formatDec(row.down) }}</span>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column label="上行上限" min-width="140">
          <template #default="{ row }">
            <span v-if="row.up_limit && row.up_limit > 0">{{ bytesPerSecToAutoUnit(row.up_limit) }}</span>
            <span v-else>-</span>
          </template>
        </el-table-column>
        <el-table-column label="下行上限" min-width="140">
          <template #default="{ row }">
            <span v-if="row.down_limit && row.down_limit > 0">{{ bytesPerSecToAutoUnit(row.down_limit) }}</span>
            <span v-else>-</span>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="120">
          <template #default="{ row }">
            <el-tag type="success" v-if="row.status === 'enabled'">正常</el-tag>
            <el-tag type="info" v-if="row.status === 'disabled'">禁用</el-tag>
            <el-tag type="warning" v-if="row.status === 'expired'">过期</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="开始时间" min-width="180">
          <template #default="{ row }">{{ row.start_date_time ?? '-' }}</template>
        </el-table-column>
        <el-table-column label="过期时间" min-width="180">
          <template #default="{ row }">{{ row.expired_date_time ?? '-' }}</template>
        </el-table-column>
        <el-table-column label="周期单位" width="120">
          <template #default="{ row }">{{ unitLabelCN(row.period_unit) }}</template>
        </el-table-column>
        <el-table-column label="剩余周期" width="120">
          <template #default="{ row }">
            <span v-if="row.period_left !== null && row.period_left !== undefined && row.period_left == -1">无限</span>
            <span v-if="row.period_left !== null && row.period_left !== undefined && row.period_left == 0 && row.period_unit == '' ">-</span>
            <span v-if="row.period_left !== null && row.period_left !== undefined && row.period_left == 0 && row.period_unit != '' ">到期不续</span>
            <span v-if="row.period_left !== null && row.period_left !== undefined && row.period_left > 0">{{ row.period_left }}</span>
          </template>
        </el-table-column>
        <el-table-column label="创建时间" min-width="180">
          <template #default="{ row }">{{ row.create_date_time ?? '-' }}</template>
        </el-table-column>
        <el-table-column label="更新时间" min-width="180">
          <template #default="{ row }">{{ row.update_date_time ?? '-' }}</template>
        </el-table-column>
        <el-table-column label="操作" width="200" fixed="right" v-if="isAdmin">
          <template #default="{ row }">
            <el-button size="small" @click="openEdit(row)">修改</el-button>
            <el-button size="small" type="danger" @click="confirmDel(row.id)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <div class="pager">
      <el-pagination background layout="prev, pager, next, ->, total" :page-size="size" :current-page="page"
        :total="total" @current-change="onPageChange" />
    </div>
  </el-card>

  <!-- 小屏全屏弹窗，正文可滚 -->
  <el-dialog v-model="dialog" :title="isEdit ? '编辑用户' : '新增用户'" :fullscreen="isSmallScreen" width="560px"
    class="user-dialog" destroy-on-close>
    <!-- 离屏“诱饵”字段，拦截浏览器自动填充 -->
    <input type="text" autocomplete="username" name="fakeuser" tabindex="-1" aria-hidden="true"
      style="position:absolute;left:-9999px;width:1px;height:1px;opacity:0;" />
    <input type="password" autocomplete="new-password" name="fakepass" tabindex="-1" aria-hidden="true"
      style="position:absolute;left:-9999px;width:1px;height:1px;opacity:0;" />

    <el-form ref="formRef" :model="form" :rules="baseRules" label-width="110px" class="user-form" autocomplete="off">
      <el-form-item label="ID" v-if="isEdit"><el-input v-model="form.id" disabled /></el-form-item>

      <el-form-item label="VMID">
        <!-- 不用 .number，允许 ''；保存时统一解析 -->
        <el-input v-model="form.vm_id" type="number" placeholder="留空=不绑定 VM" clearable />
      </el-form-item>

      <!-- 必填：新增/编辑都必填 -->
      <el-form-item label="用户名" prop="username" required>
        <el-input v-model="form.username" :name="unameName" autocomplete="off" autocapitalize="none" spellcheck="false"
          :readonly="usernameReadonly" @focus="usernameReadonly = false" placeholder="6-64 位" />
      </el-form-item>

      <!-- 一个密码框：新增必填；编辑回显原密码，不改不送 -->
      <el-form-item label="密码" :rules="passwordRules" :required="!isEdit">
        <el-input v-model="form.password" :name="passName" show-password autocomplete="new-password"
          :readonly="passwordReadonly" @focus="passwordReadonly = false" :placeholder="isEdit ? '' : '不少于 6 位'" />
      </el-form-item>

      <!-- 配额 -->
      <el-form-item label="配额">
        <div class="row-compact">
          <el-input v-model.number="quotaVal" type="number" inputmode="decimal" class="w-200" placeholder="例如 10，留空=不限"
            clearable @input="onPickQuota" @change="onPickQuota" @clear="onClearQuota" />
          <el-select v-model="quotaUnit" class="w-160" @change="onPickQuota">
            <el-option label="B" value="B" />
            <el-option label="KB (1000)" value="KB" />
            <el-option label="MB (1000²)" value="MB" />
            <el-option label="GB (1000³)" value="GB" />
            <el-option label="TB (1000⁴)" value="TB" />
          </el-select>
        </div>
      </el-form-item>

      <!-- 上/下行上限 -->
      <el-form-item label="上行上限">
        <div class="row-compact">
          <el-input v-model.number="upLimitVal" type="number" inputmode="decimal" class="w-200" placeholder="留空=不限"
            clearable @input="onPickUpLimit" @change="onPickUpLimit" @clear="onClearUpLimit" />
          <el-select v-model="upLimitUnit" class="w-160" @change="onPickUpLimit">
            <el-option v-for="u in speedUnits" :key="u" :label="u" :value="u" />
          </el-select>
        </div>
      </el-form-item>

      <el-form-item label="下行上限">
        <div class="row-compact">
          <el-input v-model.number="downLimitVal" type="number" inputmode="decimal" class="w-200" placeholder="留空=不限"
            clearable @input="onPickDownLimit" @change="onPickDownLimit" @clear="onClearDownLimit" />
          <el-select v-model="downLimitUnit" class="w-160" @change="onPickDownLimit">
            <el-option v-for="u in speedUnits" :key="u" :label="u" :value="u" />
          </el-select>
        </div>
      </el-form-item>

      <!-- 状态 -->
      <el-form-item label="状态" prop="status" required>
        <el-select v-model="form.status" style="width:200px">
          <el-option label="正常" value="enabled" />
          <el-option label="禁用" value="disabled" />
          <el-option label="过期" value="expired" />
        </el-select>
      </el-form-item>

      <!-- 开始时间（清空发送 ''） -->
      <el-form-item label="开始时间">
        <el-date-picker v-model="formStart" type="datetime" placeholder="不设置开始时间"
          format="YYYY-MM-DD HH:mm:ss" value-format="YYYY-MM-DD HH:mm:ss"
          :editable="false" clearable @change="onPickStart" @clear="onClearStart" />
      </el-form-item>

      <!-- 过期时间（清空发送 ''） -->
      <el-form-item label="过期时间">
        <el-date-picker v-model="formExpired" type="datetime" placeholder="不设置过期时间"
          format="YYYY-MM-DD HH:mm:ss" value-format="YYYY-MM-DD HH:mm:ss"
          :editable="false" clearable @change="onPick" @clear="onClear" />
      </el-form-item>

      <!-- 周期设置（中文展示） -->
      <el-form-item label="周期单位">
        <el-select v-model="periodUnit" class="w-200" clearable placeholder="不设置">
          <el-option label="天" value="day" />
          <el-option label="月" value="month" />
        </el-select>
      </el-form-item>

      <el-form-item label="剩余周期">
        <div class="row-compact">
          <el-input v-model="periodLeftVal" type="number" class="w-200" placeholder="-1=无限，0=不再续，正整数" clearable />
          <span style="opacity:.75">默认0不再续</span>
        </div>
      </el-form-item>
    </el-form>

    <template #footer>
      <el-button @click="dialog = false">取消</el-button>
      <el-button type="primary" @click="submit">保存</el-button>
    </template>
  </el-dialog>
</template>

<style scoped>
.user-card :deep(.el-card__header) { padding: 12px 16px; }
.toolbar { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.toolbar__input { width: 260px; max-width: 70vw; }
.toolbar__btns { display: flex; gap: 8px; }
.table-scroll { width: 100%; overflow-x: auto; }
.user-table { min-width: 1160px; }
.pager { margin-top: 8px; text-align: right; }
.row-compact { display: flex; gap: 8px; flex-wrap: nowrap; align-items: center; }
.w-200 { width: 200px; }
.w-160 { width: 160px; }
.user-dialog :deep(.el-dialog__body) { max-height: 70vh; overflow: auto; }

@media (max-width: 600px) {
  .toolbar__input { width: 100%; max-width: 100%; }
  .toolbar__btns { width: 100%; justify-content: flex-start; }
  .user-dialog :deep(.el-dialog__body) { max-height: calc(100vh - 120px); }
  .user-form :deep(.el-form-item__content) { flex-wrap: wrap; }
  .user-form :deep(.el-form-item__label) { width: 86px !important; }
  .row-compact { flex-wrap: wrap; }
  .w-200, .w-160 { width: 100%; }
}
.muted { color: rgba(0,0,0,.45); }
.vm-link { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
</style>
