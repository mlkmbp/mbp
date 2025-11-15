<!-- src/pages/Traffic.vue -->
<script setup lang="ts">
import { ref, onMounted, onUnmounted, computed, watch } from 'vue'
import { ElMessage } from 'element-plus'
import api from '@/api'
import { formatTime } from '@/utils/format'
import { formatIEC } from '@/utils/bytes'

/** ==============================
 *  Types
 *  ============================== */
type Opt = { label: string; value: string }
type TrafficRow = {
  id: number
  time: number
  username: string
  direction: '入站' | '出站' | string
  listen_addr: string
  listen_port: number
  protocol: string
  up: number
  down: number
  dur: number
  source_addr: string
  source_port: number
  target_addr: string
  target_port: number
}
type TrafficResp = {
  list: TrafficRow[]
  total: number
  sum_up: number
  sum_down: number
}

/** ==============================
 *  基本状态（页码分页）
 *  ============================== */
const page = ref<number>(1)
const size = ref<number>(20)          // 默认 20/页（手机更友好）
const sizeOptions = [20, 50, 100]
const total = ref(0)
const sumUp = ref(0)
const sumDown = ref(0)
const list = ref<TrafficRow[]>([])
const loading = ref(false)

const me = ref<{ id: number; username: string; is_admin: boolean } | null>(null)
const isAdmin = ref(false)
const isMobile = ref(false)
const isPad = ref(false)

/** ==============================
 *  稳定快照锚（关键）
 *  ============================== */
// 为了抵抗“增量写入”导致的 offset 漂移，固定一个“上界”快照：cap_time/cap_id
// 语义：仅查询 (time, id) <= (cap_time, cap_id) 的记录（按 time DESC, id DESC）
const capTime = ref<number | null>(null)
const capId = ref<number | null>(null)
function resetSnapshot() {
  capTime.value = null
  capId.value = null
}

/** ==============================
 *  查询条件
 *  ============================== */
const username = ref<string>('')

// PC 用范围；Mobile 用两段
const range = ref<[Date, Date] | ''>('')          // PC: datetimerange
const mStart = ref<Date | ''>('')                 // Mobile: start
const mEnd = ref<Date | ''>('')                 // Mobile: end

const showAdvanced = ref(false)
const direction = ref<string>('')                 // 入站/出站
const listenAddr = ref<string>('')                // 监听地址
const listenPort = ref<number | ''>('')           // 监听端口
const protocol = ref<string>('')                  // 协议
const sourceAddr = ref<string>('')                // 源地址
const sourcePort = ref<number | ''>('')           // 源端口
const targetAddr = ref<string>('')                // 目标地址
const targetPort = ref<number | ''>('')           // 目标端口

const protoOpts: Opt[] = [
  { label: '（全部）', value: '' },
  { label: 'tcp', value: 'tcp' },
  { label: 'udp', value: 'udp' },
  { label: 'tls-tcp', value: 'tls-tcp' },
  { label: 'http/s', value: 'http/s' },
  { label: 'tls-http/s', value: 'tls-http/s' },
  { label: 'socks5', value: 'socks5' },
  { label: 'tls-socks5', value: 'tls-socks5' },
]
const dirOpts: Opt[] = [
  { label: '（全部）', value: '' },
  { label: '入站', value: '入站' },
  { label: '出站', value: '出站' },
  { label: 'nat', value: 'nat' },
]

/** ==============================
 *  工具函数
 *  ============================== */
function todayRange(): [Date, Date] {
  const now = new Date()
  const b = new Date(now.getFullYear(), now.getMonth(), now.getDate(), 0, 0, 0, 0)
  const e = new Date(now.getFullYear(), now.getMonth(), now.getDate(), 23, 59, 59, 999)
  return [b, e]
}
function last7DaysRange(): [Date, Date] {
  const end = new Date()
  end.setHours(23, 59, 59, 999)
  const start = new Date(end.getTime() - 6 * 24 * 60 * 60 * 1000)
  start.setHours(0, 0, 0, 0)
  return [start, end]
}
function last3DaysRange(): [Date, Date] {
  const end = new Date()
  end.setHours(23, 59, 59, 999)
  const start = new Date(end.getTime() - 2 * 24 * 60 * 60 * 1000)
  start.setHours(0, 0, 0, 0)
  return [start, end]
}
function fmtHost(addr?: any, port?: any): string {
  const a = String(addr ?? '').trim()
  const pRaw = port ?? ''
  const p = (typeof pRaw === 'number') ? (pRaw > 0 ? String(pRaw) : '') : String(pRaw).trim()
  if (!a && !p) return '-'
  if (a && p) return `${a}:${p}`
  if (a) return a
  return `:${p}`
}
function formatDuration(ms?: any): string {
  const v = Number(ms ?? 0)
  if (!Number.isFinite(v)) return '-'
  const s = Math.abs(v) / 1000
  if (s < 1) return `${v} ms`
  if (s < 60) return `${s.toFixed(s < 10 ? 2 : 1)} s`
  const m = Math.floor(s / 60), sr = Math.round(s % 60)
  if (s < 3600) return sr ? `${m}m ${sr}s` : `${m}m`
  const h = Math.floor(m / 60), mr = m % 60
  if (s < 86400) return mr ? `${h}h ${mr}m` : `${h}h`
  const d = Math.floor(h / 24), hr = h % 24
  return hr ? `${d}d ${hr}h` : `${d}d`
}
function directionTip(dir: string): string {
  if (dir === '入站') return '↑ 用户→中专\n↓ 中专→用户'
  if (dir === '出站') return '↑ 中专→目标\n↓ 目标→中专'
  if (dir === 'nat') return 'nat'
  return ''
}

/** ==============================
 *  视口与尺寸
 *  ============================== */
function updateViewportFlags() {
  const w = window.innerWidth
  isMobile.value = w <= 768
  isPad.value = w > 768 && w <= 1024
}
const controlSize = computed(() => (isMobile.value ? 'small' : 'default'))
const datePopperClass = computed(() => (isMobile.value ? 'dp-mobile dp-fixed' : ''))

// PC/移动端 DatePicker 快捷范围
const rangeShortcuts = [
  { text: '今天', value: () => todayRange() },
  { text: '最近3天', value: () => last3DaysRange() },
  { text: '最近7天', value: () => last7DaysRange() },
]

// 移动端分页自适应
const pagerLayout = computed(() => (isMobile.value ? 'pager' : 'total, sizes, pager, jumper'))
const pagerCount = computed(() => (isMobile.value ? 5 : 7))
const pagerSmall = computed(() => isMobile.value)

/** ==============================
 *  权限/用户
 *  ============================== */
async function loadMe() {
  try {
    const { data } = await api.get('/me', { headers: { 'Cache-Control': 'no-cache' } })
    const id = Number(data.id ?? data.user?.id ?? 0)
    const uname = String(data.username ?? data.user?.username ?? '')
    me.value = { id, username: uname, is_admin: !!data.is_admin }
    isAdmin.value = !!data.is_admin
    if (!isAdmin.value) username.value = uname
  } catch (e: any) {
    ElMessage.error(e?.message || '加载用户信息失败')
  }
}

/** ==============================
 *  时间范围（校验与取值）
 *  ============================== */
function currentRange(): [Date, Date] | null {
  if (!isMobile.value) {
    if (Array.isArray(range.value) && range.value.length === 2) return range.value
    return null
  } else {
    if (mStart.value && mEnd.value) return [mStart.value as Date, mEnd.value as Date]
    return null
  }
}
function validateRange(showMsg = true): boolean {
  const r = currentRange()
  if (!r) return true // 允许不选 => 后端默认今天
  const [s, e] = r
  if (e.getTime() < s.getTime()) {
    showMsg && ElMessage.error('结束时间不能早于开始时间')
    return false
  }
  const ms = e.getTime() - s.getTime()
  const max = 7 * 24 * 60 * 60 * 1000
  if (ms > max) {
    showMsg && ElMessage.error('时间范围不能超过 7 天')
    return false
  }
  return true
}
function setToday(triggerLoad = true) {
  const [b, e] = todayRange()
  if (isMobile.value) { mStart.value = b; mEnd.value = e } else { range.value = [b, e] }
  if (triggerLoad) onSearch()
}
function setLast7Days(triggerLoad = true) {
  const [b, e] = last7DaysRange()
  if (isMobile.value) { mStart.value = b; mEnd.value = e } else { range.value = [b, e] }
  if (triggerLoad) onSearch()
}
function setLast3Days(triggerLoad = true) {
  const [b, e] = last3DaysRange()
  if (isMobile.value) { mStart.value = b; mEnd.value = e } else { range.value = [b, e] }
  if (triggerLoad) onSearch()
}

// 模式切换时互相同步一次
watch(isMobile, (mobile) => {
  if (mobile) {
    if (Array.isArray(range.value) && range.value.length === 2) {
      mStart.value = range.value[0]
      mEnd.value = range.value[1]
    } else {
      const [b, e] = todayRange()
      mStart.value = b; mEnd.value = e
    }
  } else {
    if (mStart.value && mEnd.value) {
      range.value = [mStart.value as Date, mEnd.value as Date]
    } else {
      range.value = todayRange()
    }
  }
})

/** ==============================
 *  加载数据（页码 + 稳定快照）
 *  ============================== */
async function load() {
  if (!validateRange()) return
  try {
    loading.value = true
    const params: any = { page: page.value, size: size.value }

    // 基本筛选
    if (isAdmin.value && username.value) {
      params.username = username.value.trim()
    } const r = currentRange()
    if (r) { params.start = r[0].getTime(); params.end = r[1].getTime() }
    if (direction.value) params.direction = direction.value
    if (listenAddr.value) params.listen_addr = listenAddr.value
    if (listenPort.value !== '' && listenPort.value != null) params.listen_port = listenPort.value
    if (protocol.value) params.protocol = protocol.value
    if (sourceAddr.value) params.source_addr = sourceAddr.value
    if (sourcePort.value !== '' && sourcePort.value != null) params.source_port = sourcePort.value
    if (targetAddr.value) params.target_addr = targetAddr.value
    if (targetPort.value !== '' && targetPort.value != null) params.target_port = targetPort.value

    // —— 关键：带上稳定快照上界 ——
    // 后端若实现 cap 过滤：(time, id) <= (cap_time, cap_id)，可确保分页稳定
    if (capTime.value != null && capId.value != null) {
      params.cap_time = capTime.value
      params.cap_id = capId.value
    }

    const { data } = await api.get<TrafficResp>('/traffic', { params })

    list.value = Array.isArray(data.list) ? data.list : []
    total.value = Number(data.total ?? 0)
    sumUp.value = Number(data.sum_up ?? 0)
    sumDown.value = Number(data.sum_down ?? 0)

    // 首次页（page=1）且尚未建立快照时，从“本页第1条”建立 cap
    if (page.value === 1 && capTime.value == null && list.value.length) {
      capTime.value = list.value[0].time
      capId.value = list.value[0].id
    }
  } catch (e: any) {
    // const msg = e?.response?.data?.message || e?.response?.data?.error || e?.message
    // ElMessage.error(msg || '加载流量数据失败')
  } finally {
    loading.value = false
  }
}

/** ==============================
 *  触发器
 *  ============================== */
function onSearch() {
  // 新查询：回到第1页，重置稳定快照
  page.value = 1
  resetSnapshot()
  load()
}

function resetFilters() {
  if (!isAdmin.value && me.value) username.value = me.value.username
  else username.value = ''
  direction.value = listenAddr.value = protocol.value = sourceAddr.value = targetAddr.value = ''
  listenPort.value = sourcePort.value = targetPort.value = ''
  setToday(false)
  page.value = 1
  resetSnapshot()
  load()
}

function onSizeChange() {
  // 改变 page size：通常仍保持同一份快照（cap* 不变），只是页划分不同
  page.value = 1
  load()
}

function onPageChange(p: number) {
  page.value = p
  load()
}

/** ==============================
 *  生命周期
 *  ============================== */
onMounted(async () => {
  updateViewportFlags()
  window.addEventListener('resize', updateViewportFlags)
  setToday(false) // 默认今天但不立刻查
  await loadMe()
  page.value = 1
  resetSnapshot()
  await load()
})
onUnmounted(() => window.removeEventListener('resize', updateViewportFlags))
</script>

<template>
  <el-card class="traffic-card" :class="{ 'is-mobile': isMobile }">
    <template #header>
      <div class="toolbar">
        <!-- 用户名 -->
        <el-input v-model="username" placeholder="用户名（留空代表全部）" class="toolbar__username" :disabled="!isAdmin" clearable
          :size="controlSize" />

        <!-- 日期：PC = 范围；Mobile = 开始/结束分行 -->
        <el-date-picker v-if="!isMobile" v-model="range" type="datetimerange" start-placeholder="开始时间"
          end-placeholder="结束时间" :shortcuts="rangeShortcuts"
          :default-time="[new Date(2000, 1, 1, 0, 0, 0), new Date(2000, 1, 1, 23, 59, 59)]" format="YYYY-MM-DD HH:mm:ss"
          :editable="false" :unlink-panels="true" clearable class="toolbar__range" :size="controlSize" />
        <div v-else class="toolbar__mobile-range">
          <el-date-picker v-model="mStart" type="datetime" placeholder="开始时间" :default-time="new Date()"
            format="YYYY-MM-DD HH:mm:ss" :editable="false" :teleported="true" :popper-class="datePopperClass" clearable
            :size="controlSize" />
          <el-date-picker v-model="mEnd" type="datetime" placeholder="结束时间" :default-time="new Date()"
            format="YYYY-MM-DD HH:mm:ss" :editable="false" :teleported="true" :popper-class="datePopperClass" clearable
            :size="controlSize" />
          <div class="toolbar__quick">
            <el-button :size="controlSize" plain @click="setToday()">今天</el-button>
            <el-button :size="controlSize" plain @click="setLast3Days()">最近3天</el-button>
            <el-button :size="controlSize" plain @click="setLast7Days()">最近7天</el-button>
            <el-button :size="controlSize" plain @click="showAdvanced = !showAdvanced">
              {{ showAdvanced ? '收起高级搜索' : '高级搜索' }}
            </el-button>
          </div>
        </div>

        <!-- PC 快捷按钮 -->
        <div v-if="!isMobile" class="toolbar__quick--pc">
          <el-button :size="controlSize" plain @click="setToday()">今天</el-button>
          <el-button :size="controlSize" plain @click="setLast3Days()">最近3天</el-button>
          <el-button :size="controlSize" plain @click="setLast7Days()">最近7天</el-button>
          <el-button :size="controlSize" plain @click="showAdvanced = !showAdvanced">
            {{ showAdvanced ? '收起高级搜索' : '高级搜索' }}
          </el-button>
        </div>

        <!-- 操作 + 每页条数 -->
        <div class="toolbar__buttons">
          <el-button type="primary" :size="controlSize" @click="onSearch()">查询</el-button>
          <el-button :size="controlSize" @click="resetFilters">重置</el-button>
        </div>

        <!-- 合计（靠左） -->
        <div class="toolbar__totals">
          <el-tag type="success" effect="plain">↑ {{ formatIEC(sumUp) }}</el-tag>
          <el-tag type="info" effect="plain">↓ {{ formatIEC(sumDown) }}</el-tag>
        </div>
      </div>

      <transition name="el-zoom-in-top">
        <div v-show="showAdvanced" class="adv-grid">
          <el-select v-model="direction" placeholder="方向" clearable filterable :size="controlSize">
            <el-option v-for="d in dirOpts" :key="d.value" :label="d.label" :value="d.value" />
          </el-select>

          <el-input v-model="listenAddr" placeholder="监听地址" :size="controlSize" />
          <el-input v-model.number="listenPort" placeholder="监听端口" :size="controlSize" />
          <el-select v-model="protocol" placeholder="协议" clearable filterable :size="controlSize">
            <el-option v-for="p in protoOpts" :key="p.value" :label="p.label" :value="p.value" />
          </el-select>

          <el-input v-model="sourceAddr" placeholder="源地址" :size="controlSize" />
          <el-input v-model.number="sourcePort" placeholder="源端口" :size="controlSize" />
          <el-input v-model="targetAddr" placeholder="目标地址" :size="controlSize" />
          <el-input v-model.number="targetPort" placeholder="目标端口" :size="controlSize" />
        </div>
      </transition>
    </template>

    <!-- 桌面：表格视图（铺满） -->
    <div v-if="!isMobile" class="table-wrap">
      <el-table :data="list" row-key="id" stripe :size="isPad ? 'small' : 'default'" :border="false"
        :default-sort="{ prop: 'time', order: 'descending' }" table-layout="auto" style="width:100%"
        v-loading="loading">
        <el-table-column prop="id" label="ID" min-width="100" />
        <el-table-column label="时间" min-width="170" show-overflow-tooltip>
          <template #default="{ row }">{{ formatTime(row.time) }}</template>
        </el-table-column>
        <el-table-column prop="username" label="用户" min-width="140" show-overflow-tooltip />
        <el-table-column label="方向" min-width="100">
          <template #default="{ row }">
            <el-tooltip :content="directionTip(row.direction)" placement="top" effect="dark">
              <el-tag :type="row.direction === '入站' ? 'success' : row.direction === 'nat' ? 'info' : 'warning'" size="small">
                {{ row.direction }}
              </el-tag>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column label="监听" min-width="200" show-overflow-tooltip>
          <template #default="{ row }">{{ fmtHost(row.listen_addr, row.listen_port) }}</template>
        </el-table-column>
        <el-table-column label="用户请求源" min-width="200" show-overflow-tooltip>
          <template #default="{ row }">{{ fmtHost(row.source_addr, row.source_port) }}</template>
        </el-table-column>
        <el-table-column label="目标" min-width="220" show-overflow-tooltip>
          <template #default="{ row }">{{ fmtHost(row.target_addr, row.target_port) }}</template>
        </el-table-column>
        <el-table-column prop="protocol" label="协议" min-width="120" show-overflow-tooltip />
        <el-table-column label="↑ + ↓" min-width="130">
          <template #default="{ row }">
            <el-tooltip :content="`${row.up + row.down} B`" placement="top">
              <span class="mono">{{ formatIEC(row.up + row.down) }}</span>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column label="↑ Bytes" min-width="130">
          <template #default="{ row }">
            <el-tooltip :content="`${row.up} B`" placement="top">
              <span class="mono">{{ formatIEC(row.up) }}</span>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column label="↓ Bytes" min-width="130">
          <template #default="{ row }">
            <el-tooltip :content="`${row.down} B`" placement="top">
              <span class="mono">{{ formatIEC(row.down) }}</span>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column label="时长" min-width="110">
          <template #default="{ row }">
            <el-tooltip :content="`${row.dur} ms`" placement="top">
              <span>{{ formatDuration(row.dur) }}</span>
            </el-tooltip>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <!-- 手机：卡片视图 -->
    <div v-else class="cards" v-loading="loading">
      <el-empty v-if="!list.length && !loading" description="没有数据" />
      <div v-for="row in list" :key="row.id" class="card">
        <div class="card__head">
          <div class="card__time">{{ formatTime(row.time) }}</div>
          <el-tag size="small" :type="row.direction === '入站' ? 'success' : 'warning'">{{ row.direction }}</el-tag>
        </div>

        <div class="kv"><span class="k">ID</span><span class="v mono">{{ row.id }}</span></div>
        <div class="kv"><span class="k">用户</span><span class="v">{{ row.username }}</span></div>
        <div class="kv"><span class="k">监听</span><span class="v">{{ fmtHost(row.listen_addr, row.listen_port) }}</span>
        </div>
        <div class="kv"><span class="k">用户请求源</span><span class="v">{{ fmtHost(row.source_addr, row.source_port)
            }}</span>
        </div>
        <div class="kv"><span class="k">目标</span><span class="v">{{ fmtHost(row.target_addr, row.target_port) }}</span>
        </div>

        <div class="card__stats">
          <el-tag size="small" type="success" effect="plain">↑ + ↓{{ formatIEC(row.up + row.down) }}</el-tag>
          <small class="raw mono">( {{ row.up + row.down }} B )</small>
          <el-tag size="small" type="success" effect="plain">↑ {{ formatIEC(row.up) }}</el-tag>
          <small class="raw mono">( {{ row.up }} B )</small>

          <el-tag size="small" type="info" effect="plain">↓ {{ formatIEC(row.down) }}</el-tag>
          <small class="raw mono">( {{ row.down }} B )</small>

          <el-tag size="small" type="info" effect="light">{{ row.protocol }}</el-tag>

          <span class="dur">
            {{ formatDuration(row.dur) }}
            <small class="raw mono">( {{ row.dur }} ms )</small>
          </span>
        </div>
      </div>
    </div>

    <!-- 页码分页（移动端自适应） -->
    <div class="pager">
      <el-pagination background :small="pagerSmall" :layout="pagerLayout" :pager-count="pagerCount" :current-page="page"
        :page-size="size" :page-sizes="sizeOptions" :total="total" :hide-on-single-page="true"
        @current-change="onPageChange" @size-change="(s: number) => { size = s; onSizeChange() }" />
    </div>
  </el-card>
</template>

<style scoped>
/* 表格：铺满 + 避免行过高 */
.table-wrap :deep(.el-table .cell) {
  white-space: nowrap;
}

.table-wrap :deep(.el-table) {
  width: 100%;
}

.table-wrap {
  width: 100%;
  overflow-x: auto;
}

.mono {
  font-variant-numeric: tabular-nums;
}

.muted {
  color: var(--el-text-color-secondary);
}

/* 顶部工具区（PC 左对齐：用户名 | 日期 | 快捷 | 按钮 | 占位） */
.toolbar {
  display: grid;
  grid-template-columns: auto auto auto auto 1fr;
  gap: 8px;
  align-items: center;
}

.toolbar__username {
  width: 220px;
}

.toolbar__range {
  width: 420px;
}

.toolbar__quick--pc {
  display: flex;
  gap: 8px;
}

.toolbar__buttons {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  align-items: center;
}

.toolbar__size {
  display: flex;
  align-items: center;
  gap: 6px;
}

.size-label {
  color: var(--el-text-color-secondary);
  font-size: 12px;
}

.toolbar__totals {
  grid-column: 1 / -1;
  display: flex;
  gap: 8px;
  justify-content: flex-start;
  margin-left: 0;
}

/* 高级搜索区 */
.adv-grid {
  margin-top: 12px;
  display: grid;
  grid-template-columns: repeat(4, minmax(180px, 1fr));
  gap: 8px;
}

/* 手机端卡片 */
.cards {
  display: grid;
  gap: 10px;
}

.card {
  border: 1px solid var(--el-border-color);
  border-radius: 10px;
  padding: 10px 12px;
}

.card__head {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 6px;
}

.card__time {
  font-weight: 600;
}

.kv {
  display: grid;
  grid-template-columns: 76px 1fr;
  gap: 8px;
  font-size: 13px;
  margin: 4px 0;
}

.k {
  color: var(--el-text-color-secondary);
}

.v {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.card__stats {
  display: flex;
  gap: 8px;
  align-items: center;
  margin-top: 8px;
  flex-wrap: wrap;
}

.dur {
  margin-left: auto;
  font-size: 12px;
  color: var(--el-text-color-secondary);
}

/* 分页 */
.pager {
  margin-top: 8px;
  text-align: right;
}

.pager :deep(.el-pagination) {
  max-width: 100%;
}

/* ===== 移动端适配 ===== */
@media (max-width: 768px) {
  .toolbar {
    grid-template-columns: 1fr !important;
    gap: 8px;
  }

  .toolbar__username {
    width: 100% !important;
  }

  /* 手机端“开始/结束”各占一行；快捷按钮可换行 */
  .toolbar__mobile-range {
    display: flex !important;
    flex-direction: column !important;
    gap: 8px !important;
  }

  :deep(.toolbar__mobile-range .el-date-editor) {
    width: 100% !important;
  }

  .toolbar__quick {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
    justify-content: flex-start;
  }

  .adv-grid {
    grid-template-columns: 1fr;
  }

  .traffic-card {
    padding-left: 6px;
    padding-right: 6px;
  }

  /* 移动端分页：左对齐 + 可横向滚动，避免挤出屏幕 */
  .pager {
    text-align: left;
    overflow-x: auto;
    -webkit-overflow-scrolling: touch;
  }
}

/* ===== 移动端 DatePicker 弹层（配合 popper-class="dp-mobile dp-fixed"）===== */
:deep(.dp-mobile) {
  width: 100vw !important;
  max-width: 100vw !important;
  left: 0 !important;
  right: 0 !important;
  margin: 0 !important;
}

:deep(.dp-mobile .el-picker-panel) {
  width: 100% !important;
  max-width: 100% !important;
  border-radius: 8px;
}

:deep(.dp-mobile .el-picker-panel__sidebar) {
  display: none !important;
}

:deep(.dp-mobile .el-date-range-picker__content.is-left) {
  display: none !important;
}

:deep(.dp-mobile .el-date-range-picker__content.is-right) {
  width: 100% !important;
  margin: 0 !important;
}

:deep(.dp-mobile .el-date-picker) {
  width: 100% !important;
}

:deep(.dp-mobile .el-picker-panel__content) {
  padding: 6px 8px !important;
}

:deep(.dp-mobile .el-picker-panel__footer) {
  padding: 6px 8px !important;
}

/* 固定定位全屏 + 去箭头 */
:deep(.dp-fixed) {
  position: fixed !important;
  inset: 0 !important;
  width: 100vw !important;
  height: 100vh !important;
  display: flex !important;
  align-items: flex-start;
  justify-content: center;
  padding: 8px;
  box-sizing: border-box;
  z-index: 3000 !important;
}

:deep(.dp-fixed .el-popper__arrow) {
  display: none !important;
}

/* 原始值（B / ms）的细灰字 */
.raw {
  color: var(--el-text-color-secondary);
  margin-left: 6px;
}

.mono {
  font-variant-numeric: tabular-nums;
}
</style>
