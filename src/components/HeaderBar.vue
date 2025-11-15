<script setup lang="ts">
import { ref, computed, onMounted, onBeforeUnmount, reactive } from 'vue'
import { Sunny, Fold, SwitchButton, Key } from '@element-plus/icons-vue'
import api from '@/api'
import ChangePasswordDialog from '@/components/ChangePasswordDialog.vue'

type Me = {
  id: number; vm_id: number; username: string;
  quota: number; up: number; down: number;
  status: 'enabled' | 'disabled' |'expired';
  start_date_time?: string;
  expired_date_time?: string;
  period_unit: 'day' | 'month' | '';
  period_left: number;

  create_date_time?: string;
  update_date_time?: string;
  is_admin: boolean;
  up_limit: number;        // Bytes/s
  down_limit: number;      // Bytes/s
}

const statusText = computed(() =>
  me.status === 'enabled' ? '正常' :
  me.status === 'expired' ? '过期' : '禁用'
)

const statusTagType = computed<'success'|'warning'|'info'>(() =>
  me.status === 'enabled' ? 'success' :
  me.status === 'expired' ? 'warning' : 'info'
)

const showPwd = ref(false)

/* 事件：适配父容器侧栏 */
const emit = defineEmits<{ (e: 'toggle-aside'): void; (e: 'force-close-aside'): void }>()
const isMobile = ref(typeof window !== 'undefined' ? window.innerWidth <= 600 : false)
function onResize() { isMobile.value = window.innerWidth <= 600 }

/* ========= 本地格式化 ========= */
function formatBytesSI(bytes?: number | null): string {
  const n = Number(bytes || 0)
  if (!Number.isFinite(n) || n < 0) return '0 B'
  if (n < 1000) return `${n} B`
  const u = ['KB', 'MB', 'GB', 'TB']; let v = n / 1000, i = 0
  while (v >= 1000 && i < u.length - 1) { v /= 1000; i++ }
  return `${v.toFixed(v >= 100 ? 0 : v >= 10 ? 1 : 2)} ${u[i]}`
}
function bytesPerSecToAdaptiveBpsLabel(bpsBytes?: number | null): string {
  const n = Number(bpsBytes || 0); if (!Number.isFinite(n) || n <= 0) return '—'
  const bps = n * 8; if (bps < 1000) return '<1 Kbps'
  const u = ['Kbps', 'Mbps', 'Gbps', 'Tbps']; let v = bps / 1000, i = 0
  while (v >= 1000 && i < u.length - 1) { v /= 1000; i++ }
  return `${Number(v.toFixed(v >= 100 ? 0 : v >= 10 ? 1 : 2))} ${u[i]}`
}

/* ========= 状态 ========= */
const me = reactive<Me>({
  id: 0, vm_id: 0, username: '', quota: 0, up: 0, down: 0,
  status: 'enabled', period_unit: '', period_left: 0,
  start_date_time: '', expired_date_time: '', create_date_time: '', update_date_time: '',
  is_admin: false, up_limit: 0, down_limit: 0,
})

const upUsed = computed(() => me.up || 0)
const downUsed = computed(() => me.down || 0)
const totalUsed = computed(() => upUsed.value + downUsed.value)

const quotaText = computed(() => {
  if (!me.quota || me.quota <= 0) {
    return `不限（已用：上行 ${formatBytesSI(upUsed.value)} / 下行 ${formatBytesSI(downUsed.value)}，总共 ${formatBytesSI(totalUsed.value)}）`
  }
  return `${formatBytesSI(totalUsed.value)} / ${formatBytesSI(me.quota)}`
})
const percent = computed<number | null>(() => {
  if (!me.quota || me.quota <= 0) return null
  return Math.min(100, Math.max(0, Math.round(totalUsed.value * 100 / me.quota)))
})
const percentStatus = computed<'success' | 'warning' | 'exception'>(() => {
  if (percent.value == null) return 'success'
  if (percent.value < 70) return 'success'
  if (percent.value < 90) return 'warning'
  return 'exception'
})

const upLimitLabel = computed(() => me.up_limit > 0 ? bytesPerSecToAdaptiveBpsLabel(me.up_limit) : '')
const downLimitLabel = computed(() => me.down_limit > 0 ? bytesPerSecToAdaptiveBpsLabel(me.down_limit) : '')

/* ========= /me 加载 ========= */
const showLoading = ref(false)
const firstLoad = ref(true)
let loadingTimer: number | null = null
function beginSmartLoading() {
  if (!firstLoad.value) return
  if (loadingTimer) clearTimeout(loadingTimer)
  loadingTimer = window.setTimeout(() => (showLoading.value = true), 300)
}
function endSmartLoading() {
  if (loadingTimer) { clearTimeout(loadingTimer); loadingTimer = null }
  showLoading.value = false; firstLoad.value = false
}

function patchMe(raw: any) {
  const u = (raw?.user ?? raw) || {}
  const num = (v: any) => Number(v || 0)
  const str = (v: any) => (v ?? '') + ''

  me.id = num(u.id)
  me.vm_id = num(u.vm_id)                                // 补齐
  me.username = str(u.username)
  me.quota = num(u.quota)
  me.up = num(u.up)
  me.down = num(u.down)
  me.status = (u.status ?? 'enabled')

  me.start_date_time = str(u.start_date_time)            // 补齐
  me.expired_date_time = str(u.expired_date_time)
  me.create_date_time = str(u.create_date_time)
  me.update_date_time = str(u.update_date_time)

  me.period_unit = (u.period_unit ?? '')                 // 补齐
  me.period_left = Number.isFinite(u.period_left) ? Number(u.period_left) : 0 // 补齐

  me.is_admin = !!u.is_admin
  me.up_limit = num(u.up_limit)
  me.down_limit = num(u.down_limit)
}

async function loadMe() {
  beginSmartLoading()
  try {
    const { data } = await api.get('/me', {
      headers: { 'Cache-Control': 'no-cache', 'X-Silent': '1' }, // 静默
    })
    patchMe(data)
  } catch {
    // 静默吞错：不提示、不打断轮询
  } finally {
    endSmartLoading()
  }
}

/* ========= 主题 / 会话 ========= */
function toggleTheme() {
  const el = document.documentElement
  const dark = el.classList.toggle('dark')
  localStorage.setItem('theme', dark ? 'dark' : 'light')
}
function initTheme() { if (localStorage.getItem('theme') === 'dark') document.documentElement.classList.add('dark') }
function logout() { localStorage.removeItem('token'); location.href = '/login' }

/* ========= 5 秒轮询（仅可见时） ========= */
const REFRESH_MS = 5000
let pollTimer: ReturnType<typeof setTimeout> | null = null
let inFlight = false
function scheduleNext(delay = REFRESH_MS) {
  if (pollTimer) clearTimeout(pollTimer)
  pollTimer = setTimeout(tick, delay)
}
async function tick() {
  if (document.visibilityState !== 'visible') { scheduleNext(); return }
  if (inFlight) { scheduleNext(); return }
  inFlight = true
  try {
    await loadMe()                // ★ 实际执行刷新
  } finally {
    inFlight = false
    scheduleNext()
  }
}
function onVisChange() {
  if (document.visibilityState === 'visible') {
    if (pollTimer) { clearTimeout(pollTimer); pollTimer = null }
    tick() // 立刻刷新一次
  }
}
const unitLabelCN = (u: any) => (u === 'day' ? '天' : u === 'month' ? '月' : '-')

/* ========= 详情弹窗 ========= */
const showDetail = ref(false)
function openDetail() { showDetail.value = true }

/* ========= 首次移动端强制收起侧栏（只关闭，不 toggle） ========= */
function forceCloseAsideOnMobileOnce() {
  if (!isMobile.value) return
  if (sessionStorage.getItem('__aside_closed_once__')) return
  emit('force-close-aside') // 只发关闭
  sessionStorage.setItem('__aside_closed_once__', '1')
}

/* ========= 生命周期 ========= */
onMounted(() => {
  if (!localStorage.getItem('token')) return
  initTheme(); onResize()
  window.addEventListener('resize', onResize)
  window.addEventListener('orientationchange', onResize)

  loadMe().finally(() => scheduleNext()) // 首次加载 + 开启 5s 轮询
  document.addEventListener('visibilitychange', onVisChange)

  forceCloseAsideOnMobileOnce()
})
onBeforeUnmount(() => {
  if (pollTimer) { clearTimeout(pollTimer); pollTimer = null }
  document.removeEventListener('visibilitychange', onVisChange)
  window.removeEventListener('resize', onResize)
  window.removeEventListener('orientationchange', onResize)
})
</script>

<template>
  <div class="hdr" v-loading="showLoading">
    <!-- 左：菜单按钮 -->
    <el-button class="icon-btn" text @click="emit('toggle-aside')" :icon="Fold" />

    <!-- 中：桌面信息块（简洁；点击查看详情） -->
    <div class="user desktop-only" @click="openDetail" style="cursor:pointer;">
      <div class="avatar">{{ (me.username || '?').charAt(0).toUpperCase() }}</div>
      <div class="meta">
        <div class="r1">
          <span class="name">{{ me.username || '-' }}</span>
          <el-tag size="small" :type="statusTagType">{{ statusText }}</el-tag>

          <el-tag size="small" type="warning" effect="dark">{{ me.is_admin ? '管理员' : '普通用户' }}</el-tag>
          <span class="muted">ID: {{ me.id || '-' }}</span>
        </div>
        <div class="r2">
          <span class="muted">配额：</span><b>{{ quotaText }}</b>
          <span class="muted ml8">开始：</span><span class="mono">{{ me.start_date_time || '-' }}</span>
          <span class="muted ml8">过期：</span><span class="mono">{{ me.expired_date_time || '-' }}</span>
        </div>
        <div class="r3">
          <el-tag v-if="upLimitLabel" size="small" type="info">↑ {{ upLimitLabel }}</el-tag>
          <el-tag v-if="downLimitLabel" size="small" type="info">↓ {{ downLimitLabel }}</el-tag>
        </div>
      </div>
    </div>

    <!-- 中：手机精简（点开看详情） -->
    <div class="user-mobile mobile-only" @click="openDetail" style="cursor:pointer;">
      <span class="name">{{ me.username || '-' }}</span>
      <el-tag size="small" :type="statusTagType">{{ statusText }}</el-tag>

    </div>

    <!-- 右：操作 -->
    <div class="ops">
      <el-tooltip content="切换主题" placement="bottom">
        <el-button class="icon-btn" circle text @click="toggleTheme"><el-icon><Sunny /></el-icon></el-button>
      </el-tooltip>
      <el-tooltip content="修改密码" placement="bottom">
        <el-button class="icon-btn" circle text @click="showPwd = true"><el-icon><Key /></el-icon></el-button>
      </el-tooltip>
      <ChangePasswordDialog v-model="showPwd" />
      <el-button class="quit-btn" text type="danger" @click="logout" :icon="SwitchButton">
        <span class="desktop-only">退出</span>
      </el-button>
    </div>

    <!-- 账户详情（含进度条） -->
    <el-dialog v-model="showDetail" title="账户详情" width="520px" :fullscreen="isMobile">
      <div class="detail">
        <div><b>用户名：</b>{{ me.username || '-' }}</div>
        <div><b>用户ID：</b>{{ me.id || '-' }}</div>
        <div><b>VMID：</b>{{ me.vm_id || '-' }}</div>

        <div><b>状态：</b>{{ statusText }}</div>
        <div><b>角色：</b>{{ me.is_admin ? '管理员' : '普通用户' }}</div>
        <el-divider />
        <div><b>配额：</b>{{ quotaText }}</div>
        <div v-if="percent !== null" class="detail-progress">
          <el-progress :percentage="percent" :status="percentStatus" :stroke-width="10" />
        </div>
        <div><b>已用上行：</b>{{ formatBytesSI(upUsed) }}</div>
        <div><b>已用下行：</b>{{ formatBytesSI(downUsed) }}</div>
        <div><b>上行限速：</b>{{ upLimitLabel || '—' }}</div>
        <div><b>下行限速：</b>{{ downLimitLabel || '—' }}</div>
        <el-divider />
        <div><b>周期单位：</b>{{ unitLabelCN(me.period_unit) }}</div>
        <div><b>剩余周期：</b>
          <span v-if="me.period_left !== null && me.period_left !== undefined && me.period_left == -1">无限</span>
          <span v-if="me.period_left !== null && me.period_left !== undefined && me.period_left == 0 && me.period_unit == '' ">-</span>
          <span v-if="me.period_left !== null && me.period_left !== undefined && me.period_left == 0 && me.period_unit != '' ">到期不续</span>
          <span v-if="me.period_left !== null && me.period_left !== undefined && me.period_left > 0">{{ me.period_left }}</span>
        </div>
        <el-divider />
        <div><b>开始时间：</b>{{ me.start_date_time || '—' }}</div>
        <div><b>过期时间：</b>{{ me.expired_date_time || '—' }}</div>
        <div><b>创建时间：</b>{{ me.create_date_time || '—' }}</div>
        <div><b>更新时间：</b>{{ me.update_date_time || '—' }}</div>
      </div>
      <template #footer><el-button @click="showDetail = false">关闭</el-button></template>
    </el-dialog>
  </div>
</template>

<style scoped>
/* 头部自适应高度 + 可换行，桌面不遮挡、手机不挤爆 */
.hdr {
  min-height: 64px;
  height: auto;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 8px 12px;
  border-bottom: 1px solid var(--el-border-color);
  gap: 8px;
  flex-wrap: wrap;
}

.icon-btn :deep(.el-icon) {
  font-size: 18px;
}

.user {
  display: flex;
  align-items: center;
  gap: 10px;
}

.avatar {
  width: 36px;
  height: 36px;
  border-radius: 50%;
  background: var(--el-color-primary);
  color: #fff;
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 700;
}

.meta {
  display: flex;
  flex-direction: column;
  gap: 6px;
  min-width: 420px;
}

.r1, .r2, .r3 {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
  color: var(--el-text-color-secondary);
}

.r1 .name {
  font-weight: 700;
  font-size: 14px;
  color: var(--el-text-color-primary);
}

.muted { color: var(--el-text-color-secondary); }
.mono { font-variant-numeric: tabular-nums; }
.ml8 { margin-left: 8px; }

.ops {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}
.ops :deep(.el-button) { margin-left: 0; }

.mobile-only { display: none; }
.desktop-only { display: initial; }

.detail {
  display: grid;
  grid-template-columns: 1fr;
  gap: 6px;
}
.detail-progress { margin: 4px 0 8px; }

@media (max-width: 600px) {
  .desktop-only { display: none !important; }
  .mobile-only {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
  }
  .user-mobile .name { font-weight: 700; }
  .icon-btn { padding: 6px; }
  .quit-btn { padding: 6px 8px; }
  .meta { min-width: unset; }
}
</style>
