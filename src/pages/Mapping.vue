<script setup lang="ts">
import { ref, onMounted, onBeforeUnmount } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import api from '@/api'

type RuleRow = {
  id: number
  protocol: string
  // 后端拆开的字段
  listen_addr: string
  listen_port: number
  target_addr: string
  target_port: number
  // 兼容旧字段
  listen?: string
  target?: string
  status: 'enabled' | 'disabled'
  owner_id: number
  owner: string
  bind_count: number
  bind_peek: string
}
type UserLite = { id:number; username:string; bind_count?:number; bind_peek?:string }

/** ======================= 小屏检测（弹窗全屏/布局切换） ======================= **/
const isSmallScreen = ref(typeof window !== 'undefined' ? window.innerWidth <= 600 : false)
function onResize(){ isSmallScreen.value = window.innerWidth <= 600 }
onMounted(()=> window.addEventListener('resize', onResize))
onBeforeUnmount(()=> window.removeEventListener('resize', onResize))

/** ======================= 模式切换 ======================= **/
const mode = ref<'rule'|'user'>('rule')

/** ======================= 工具函数 ======================= **/
function fmtHostPort(addr?: any, port?: any): string {
  const a = String(addr ?? '').trim()
  const p = Number(port ?? 0)
  if (!a && (!Number.isFinite(p) || p <= 0)) return '-'
  if (a && (!Number.isFinite(p) || p <= 0)) return a
  if (!a && (Number.isFinite(p) && p > 0)) return `:${p}`
  return `${a}:${p}`
}

/** ======================= 规则主：列表筛选/分页 ======================= **/
const qProtocol   = ref<string>('')    // 精确：tcp/udp/...
const qListenAddr = ref<string>('')    // 单独字段
const qListenPort = ref<number|''>('') // 单独字段
const qTargetAddr = ref<string>('')    // 单独字段
const qTargetPort = ref<number|''>('') // 单独字段
const page = ref(1)
const size = ref(10)
const total = ref(0)
const loading = ref(false)
const rule = ref<RuleRow[]>([])

async function loadRuleList() {
  try {
    loading.value = true
    const params:any = { page: page.value, size: size.value }
    if (qProtocol.value)   params.protocol     = qProtocol.value
    if (qListenAddr.value) params.listen_addr  = qListenAddr.value
    if (qListenPort.value !== '' && qListenPort.value != null) params.listen_port = Number(qListenPort.value)
    if (qTargetAddr.value) params.target_addr  = qTargetAddr.value
    if (qTargetPort.value !== '' && qTargetPort.value != null) params.target_port = Number(qTargetPort.value)
    const { data } = await api.get('/rule-binding', { params })
    rule.value = data.list || []
    total.value = Number(data.total || 0)
  } catch (e:any) {
    // ElMessage.error(e?.message || '加载失败')
  } finally {
    loading.value = false
  }
}

/** ======================= 规则主：绑定管理弹窗 ======================= **/
const dlgVisible = ref(false)
const curRuleId  = ref<number>(0)
const curRuleTitle = ref<string>('')

const bindLoading = ref(false)
const bindPage = ref(1)
const bindSize = ref(10)
const bindTotal = ref(0)
const bindList = ref<UserLite[]>([])
const owner = ref<UserLite | null>(null)

// 右侧：候选用户
const userLoading = ref(false)
const userQ   = ref<string>('')
const userPage = ref(1)
const userSize = ref(10)
const userTotal = ref(0)
const user = ref<UserLite[]>([])

const selected = ref<Set<number>>(new Set())
function isSelected(id:number){ return selected.value.has(id) }
function toggleSelect(u:UserLite){
  if (u.id === owner.value?.id) return
  if (selected.value.has(u.id)) selected.value.delete(u.id)
  else selected.value.add(u.id)
}
function selectPage() {
  const boundSet = new Set<number>(bindList.value.map(u=>u.id))
  if (owner.value) boundSet.add(owner.value.id)
  for (const u of user.value) if (!boundSet.has(u.id)) selected.value.add(u.id)
}
function clearSelected() { selected.value.clear() }

const allSelecting = ref(false)
async function selectAllResults() {
  try {
    allSelecting.value = true
    const first = await api.get('/user/search', { params: { q: userQ.value, page: 1, size: 1 } })
    const totaluser = Number(first.data?.total || 0)
    const boundSet = new Set<number>(bindList.value.map(u=>u.id))
    if (owner.value) boundSet.add(owner.value.id)
    if (!totaluser) { selected.value.clear(); return }
    const per = 500
    const pages = Math.ceil(totaluser / per)
    const allIds:number[] = []
    for (let p=1; p<=pages; p++) {
      const { data } = await api.get('/user/search', { params: { q: userQ.value, page: p, size: per } })
      for (const u of (data.list || []) as UserLite[]) {
        if (!boundSet.has(u.id)) allIds.push(u.id)
      }
    }
    selected.value = new Set(allIds)
    ElMessage.success(`已选中 ${selected.value.size} 人`)
  } catch (e:any) {
    // ElMessage.error(e?.message || '全选失败')
  } finally {
    allSelecting.value = false
  }
}

async function loadBindings() {
  if (!curRuleId.value) return
  try {
    bindLoading.value = true
    const { data } = await api.get(`/rule/${curRuleId.value}/binding`, {
      params: { page: bindPage.value, size: bindSize.value }
    })
    owner.value = data.owner?.id ? { id:Number(data.owner.id), username:String(data.owner.username||'') } : null
    const list = (data.list || []) as UserLite[]
    bindList.value = list
    bindTotal.value = Number(data.total || list.length || 0)
    const current = new Set<number>()
    for (const u of list) if (u.id !== owner.value?.id) current.add(u.id)
    selected.value = current
  } catch (e:any) {
    // ElMessage.error(e?.message || '加载已绑定失败')
  } finally {
    bindLoading.value = false
  }
}
async function loaduser() {
  try {
    userLoading.value = true
    const { data } = await api.get('/user/search', {
      params: { q: userQ.value, page: userPage.value, size: userSize.value }
    })
    const raw = (data.list || []) as UserLite[]
    const boundSet = new Set<number>(bindList.value.map(u=>u.id))
    if (owner.value) boundSet.add(owner.value.id)
    user.value = raw.filter(u => !boundSet.has(u.id))
    userTotal.value = Number(data.total || raw.length || 0)
  } catch (e:any) {
    // ElMessage.error(e?.message || '加载用户失败')
  } finally {
    userLoading.value = false
  }
}

async function openBindings(row: RuleRow) {
  curRuleId.value = row.id
  curRuleTitle.value = `规则 #${row.id}  ${fmtHostPort(row.listen_addr, row.listen_port)}  →  ${fmtHostPort(row.target_addr, row.target_port)}`
  bindPage.value = 1
  userPage.value = 1
  userQ.value = ''
  dlgVisible.value = true
  await loadBindings()
  await loaduser()
}

// 与当前已绑定比较，完全相同则不提交
function sameAsCurrentSelection(): boolean {
  const current = new Set<number>(bindList.value.map(u=>u.id).filter(id => id !== owner.value?.id))
  if (current.size !== selected.value.size) return false
  for (const id of selected.value) if (!current.has(id)) return false
  return true
}

async function saveReplace() {
  try {
    if (sameAsCurrentSelection()) {
      ElMessage.info('未发生改动，无需保存')
      return
    }
    await ElMessageBox.confirm(
      '将以当前选择覆盖该规则的「非主绑定人」映射。\n主绑定人不会受影响。\n确认继续？',
      '覆盖保存',
      { type:'warning' }
    )
    const user_ids = Array.from(selected.value)
    await api.put(`/rule/${curRuleId.value}/binding`, { user_ids })
    ElMessage.success('已保存')
    await loadBindings()
    await loaduser()
  } catch (e:any) {
    // if (e?.message && e?.message !== 'cancel') ElMessage.error(e.message)
  }
}
async function addOne(u:UserLite) {
  try {
    await api.post(`/rule/${curRuleId.value}/binding`, { user_id: Number(u.id) })
    selected.value.add(u.id)
    await loadBindings()
    await loaduser()
  } catch (e:any) {
    // ElMessage.error(e?.message || '添加失败')
  }
}
async function delOne(u:UserLite) {
  try {
    await api.delete(`/rule/${curRuleId.value}/binding/${Number(u.id)}`)
    selected.value.delete(u.id)
    await loadBindings()
    await loaduser()
  } catch (e:any) {
    // ElMessage.error(e?.message || '删除失败')
  }
}

/** ======================= 用户主 ======================= **/
const uq = ref<string>('')         // 仅映射 q
const uPage = ref(1)
const uSize = ref(10)
const uTotal = ref(0)
const uLoading = ref(false)
const userRows = ref<UserLite[]>([])

async function loadUserList() {
  try {
    uLoading.value = true
    const { data } = await api.get('/user-binding', { params: { q: uq.value, page: uPage.value, size: uSize.value } })
    userRows.value = data.list || []
    uTotal.value = Number(data.total || 0)
  } catch {} finally {
    uLoading.value = false
  }
}

const uDlgVisible = ref(false)
const curUserId = ref<number>(0)
const curUserName = ref<string>('')

const uBindLoading = ref(false)
const uBindPage = ref(1)
const uBindSize = ref(10)
const uBindTotal = ref(0)
const uBindrule = ref<RuleRow[]>([])

// 候选规则筛选（各自独立）
const rLoading = ref(false)
const rQProtocol   = ref<string>('')
const rQListenAddr = ref<string>('')
const rQListenPort = ref<number|''>('')
const rQTargetAddr = ref<string>('')
const rQTargetPort = ref<number|''>('')
const rPage = ref(1)
const rSize = ref(10)
const rTotal = ref(0)
const rrule = ref<RuleRow[]>([])

const rSelected = ref<Set<number>>(new Set())
function rIsSelected(id:number){ return rSelected.value.has(id) }
function rToggleSelect(r:RuleRow){ rSelected.value.has(r.id) ? rSelected.value.delete(r.id) : rSelected.value.add(r.id) }
function rSelectPage(){ for (const r of rrule.value) rSelected.value.add(r.id) }
function rClearSelected(){ rSelected.value.clear() }

async function openUserBindings(row:UserLite){
  curUserId.value = row.id
  curUserName.value = row.username
  uBindPage.value = 1
  rPage.value = 1
  rQProtocol.value = ''
  rQListenAddr.value = ''
  rQListenPort.value = ''
  rQTargetAddr.value = ''
  rQTargetPort.value = ''
  uDlgVisible.value = true
  await loadUserBindings()
  await loadRuleCandidates()
}
async function loadUserBindings(){
  try {
    uBindLoading.value = true
    const { data } = await api.get(`/user/${Number(curUserId.value)}/rule`, { params: { page: uBindPage.value, size: uBindSize.value } })
    uBindrule.value = data.list || []
    uBindTotal.value = Number(data.total || 0)
    rSelected.value = new Set((uBindrule.value || []).map(r => Number(r.id)))
  } catch {} finally { uBindLoading.value = false }
}
async function loadRuleCandidates(){
  try {
    rLoading.value = true
    const params:any = { page: rPage.value, size: rSize.value }
    if (rQProtocol.value)   params.protocol     = rQProtocol.value
    if (rQListenAddr.value) params.listen_addr  = rQListenAddr.value
    if (rQListenPort.value !== '' && rQListenPort.value != null) params.listen_port = Number(rQListenPort.value)
    if (rQTargetAddr.value) params.target_addr  = rQTargetAddr.value
    if (rQTargetPort.value !== '' && rQTargetPort.value != null) params.target_port = Number(rQTargetPort.value)
    const { data } = await api.get('/rule/search', { params })
    const boundSet = new Set<number>(uBindrule.value.map(r=>Number(r.id)))
    const raw = (data.list || []) as RuleRow[]
    rrule.value = raw.filter(r => !boundSet.has(Number(r.id)))
    rTotal.value = Number(data.total || raw.length || 0)
  } catch {} finally { rLoading.value = false }
}

// 与当前选择一致就不提交
function rSameAsCurrent(): boolean {
  const current = new Set<number>(uBindrule.value.map(r=>Number(r.id)))
  if (current.size !== rSelected.value.size) return false
  for (const id of rSelected.value) if (!current.has(id)) return false
  return true
}

async function uSaveReplace(){
  try {
    if (rSameAsCurrent()) {
      ElMessage.info('未发生改动，无需保存')
      return
    }
    await ElMessageBox.confirm(
      '将以当前选择覆盖该用户的规则绑定。\n该用户作为 OWNER 的规则不会被移除。\n确认继续？',
      '覆盖保存',
      { type:'warning' }
    )
    const rule_ids = Array.from(rSelected.value)
    await api.put(`/user/${Number(curUserId.value)}/rule`, { rule_ids })
    ElMessage.success('已保存')
    await loadUserBindings()
    await loadRuleCandidates()
  } catch (e:any) {
    // if (e?.message && e?.message !== 'cancel') ElMessage.error(e.message)
  }
}
async function uAddOne(r:RuleRow){
  try {
    await api.post(`/user/${Number(curUserId.value)}/rule`, { rule_id: Number(r.id) })
    rSelected.value.add(Number(r.id))
    await loadUserBindings()
    await loadRuleCandidates()
  } catch {}
}
async function uDelOne(r:RuleRow){
  try {
    await api.delete(`/user/${Number(curUserId.value)}/rule/${Number(r.id)}`)
    rSelected.value.delete(Number(r.id))
    await loadUserBindings()
    await loadRuleCandidates()
  } catch {}
}

/** ======================= 生命周期 ======================= **/
onMounted(() => {
  if (mode.value === 'rule') loadRuleList()
})
</script>

<template>
  <el-card>
    <template #header>
      <div class="toolbar">
        <!-- 模式切换 -->
        <el-radio-group v-model="mode" @change="()=>{ if(mode==='rule'){ page=1; loadRuleList() } else { uPage=1; loadUserList() } }">
          <el-radio-button label="rule">规则主</el-radio-button>
          <el-radio-button label="user">用户主</el-radio-button>
        </el-radio-group>

        <!-- 规则主：筛选 -->
        <template v-if="mode==='rule'">
          <el-select v-model="qProtocol" placeholder="协议" clearable class="w-140" :teleported="true" popper-class="mb-popper">
            <el-option value="tcp" label="tcp"/>
            <el-option value="udp" label="udp"/>
            <el-option value="socks5" label="socks5"/>
            <el-option value="tls-socks5" label="tls-socks5"/>
            <el-option value="http" label="http"/>
            <el-option value="https" label="https"/>
          </el-select>
          <el-input v-model="qListenAddr" placeholder="监听 IP" clearable class="w-170"/>
          <el-input v-model.number="qListenPort" placeholder="监听端口" clearable class="w-120"/>
          <el-input v-model="qTargetAddr" placeholder="目标 IP" clearable class="w-170"/>
          <el-input v-model.number="qTargetPort" placeholder="目标端口" clearable class="w-120"/>
          <el-button type="primary" @click="page=1;loadRuleList()">查询</el-button>
        </template>

        <!-- 用户主：筛选 -->
        <template v-else>
          <el-input v-model="uq" placeholder="搜索用户名" clearable class="w-240"
            @keyup.enter="uPage=1;loadUserList()" @clear="uPage=1;loadUserList()" />
          <el-button type="primary" @click="uPage=1;loadUserList()">查询</el-button>
        </template>
      </div>
    </template>

    <!-- 规则主：规则表（横向可滚） -->
    <div v-if="mode==='rule'" class="table-scroll">
      <el-table :data="rule" v-loading="loading" border class="minw-1000">
        <el-table-column prop="id" label="ID" width="80"/>
        <el-table-column prop="protocol" label="协议" width="110"/>
        <el-table-column label="监听" min-width="200" show-overflow-tooltip>
          <template #default="{row}">{{ fmtHostPort(row.listen_addr, row.listen_port) }}</template>
        </el-table-column>
        <el-table-column label="目标" min-width="200" show-overflow-tooltip>
          <template #default="{row}">{{ fmtHostPort(row.target_addr, row.target_port) }}</template>
        </el-table-column>
        <el-table-column label="绑定用户" min-width="220">
          <template #default="{row}">
            <span>{{ row.bind_count }}</span>
            <span v-if="row.bind_peek" class="peek">（{{ row.bind_peek }}）</span>
          </template>
        </el-table-column>
        <el-table-column label="主绑定人" width="160">
          <template #default="{row}">
            <el-tag type="warning" v-if="row.owner">{{ row.owner }}</el-tag>
            <span v-else style="color:#999;">无</span>
          </template>
       </el-table-column>
        <el-table-column label="状态" width="100">
          <template #default="{row}">
            <el-tag type="success" v-if="row.status==='enabled'">启用</el-tag>
            <el-tag type="info" v-else>禁用</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="140" fixed="right">
          <template #default="{row}">
            <el-button size="small" @click="openBindings(row)">管理绑定</el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <div v-if="mode==='rule'" class="pager">
      <el-pagination
        background
        layout="prev, pager, next, ->, total"
        :page-size="size"
        :current-page="page"
        :total="total"
        @current-change="(p:number)=>{ page=p; loadRuleList() }"
      />
    </div>

    <!-- 用户主：用户表（横向可滚） -->
    <div v-else class="table-scroll">
      <el-table :data="userRows" v-loading="uLoading" border class="minw-800">
        <el-table-column prop="id" label="ID" width="90"/>
        <el-table-column prop="username" label="用户名" min-width="180" show-overflow-tooltip />
        <el-table-column label="已绑定规则" min-width="240">
          <template #default="{row}">
            <span>{{ row.bind_count ?? 0 }}</span>
            <span v-if="row.bind_peek" class="peek">（{{ row.bind_peek }}）</span>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="140" fixed="right">
          <template #default="{row}">
            <el-button size="small" @click="openUserBindings(row)">管理规则</el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <div v-if="mode==='user'" class="pager">
      <el-pagination
        background
        layout="prev, pager, next, ->, total"
        :page-size="uSize"
        :current-page="uPage"
        :total="uTotal"
        @current-change="(p:number)=>{ uPage=p; loadUserList() }"
      />
    </div>
  </el-card>

  <!-- 规则主：弹窗 -->
  <el-dialog
    v-model="dlgVisible"
    :title="curRuleTitle"
    :fullscreen="isSmallScreen"
    width="90vw"
    :modal-class="'binding-dialog'"
  >
    <div class="bindings-grid">
      <!-- 左：已绑定（含 OWNER） -->
      <div class="panel">
        <div style="margin-bottom:6px;">
          <b>已绑定用户</b>
          <span v-if="owner" style="margin-left:12px; color:var(--el-text-color-secondary);">
            主绑定人：<el-tag type="warning">{{ owner.username }}</el-tag>
          </span>
        </div>

        <el-table :data="bindList" v-loading="bindLoading" height="100%" border>
          <el-table-column prop="id" label="ID" width="90" />
          <el-table-column prop="username" label="用户名" min-width="160" show-overflow-tooltip />
          <el-table-column label="操作" width="120" fixed="right">
            <template #default="{row}">
              <el-button v-if="row.id !== owner?.id" type="danger" link @click="delOne(row)">移除</el-button>
              <el-tag v-else type="warning">OWNER</el-tag>
            </template>
          </el-table-column>
        </el-table>

        <div class="panel-footer">
          <el-pagination
            background
            layout="prev, pager, next, ->, total"
            :page-size="bindSize"
            :current-page="bindPage"
            :total="bindTotal"
            @current-change="(p:number)=>{ bindPage=p; loadBindings(); loaduser(); }"
          />
        </div>
      </div>

      <!-- 右：可选用户 -->
      <div class="panel">
        <div class="tools-inline">
          <b>选择用户</b>
          <el-input v-model="userQ" placeholder="搜索用户名" clearable class="w-220"
            @keyup.enter="userPage=1; loaduser()" @clear="userPage=1; loaduser()"/>
          <el-button @click="userPage=1; loaduser()">搜索</el-button>
          <el-button @click="selectPage()">全选本页</el-button>
          <el-button @click="clearSelected()">清空选择</el-button>
          <el-button :loading="allSelecting" @click="selectAllResults()">全选全部</el-button>
        </div>

        <el-table :data="user" v-loading="userLoading" height="100%" border>
          <el-table-column label="选" width="60">
            <template #default="{row}">
              <el-checkbox :model-value="isSelected(row.id)" @change="toggleSelect(row)"/>
            </template>
          </el-table-column>
          <el-table-column prop="id" label="ID" width="90"/>
          <el-table-column prop="username" label="用户名" min-width="180" show-overflow-tooltip />
          <el-table-column label="操作" width="120" fixed="right">
            <template #default="{row}">
              <el-button type="primary" link @click="addOne(row)">添加</el-button>
            </template>
          </el-table-column>
        </el-table>

        <div class="panel-footer">
          <el-pagination
            background
            layout="prev, pager, next, ->, total"
            :page-size="userSize"
            :current-page="userPage"
            :total="userTotal"
            @current-change="(p:number)=>{ userPage=p; loaduser() }"
          />
        </div>
        <div style="margin-top:6px; color:var(--el-text-color-secondary);">
          已选择：{{ selected.size }} 人（不含主绑定人）
        </div>
      </div>
    </div>

    <template #footer>
      <el-button @click="dlgVisible=false">关闭</el-button>
      <el-button type="primary" @click="saveReplace">
        覆盖保存（不影响主绑定人）
      </el-button>
    </template>
  </el-dialog>

  <!-- 用户主：弹窗（规则绑定） -->
  <el-dialog
    v-model="uDlgVisible"
    :title="`用户 #${curUserId}  ${curUserName}`"
    :fullscreen="isSmallScreen"
    width="90vw"
    :modal-class="'binding-dialog'"
  >
    <div class="bindings-grid">
      <!-- 左：已绑定规则 -->
      <div class="panel">
        <b style="margin-bottom:6px;">已绑定规则</b>

        <el-table :data="uBindrule" v-loading="uBindLoading" height="100%" border>
          <el-table-column prop="id" label="ID" width="90"/>
          <el-table-column prop="protocol" label="协议" width="110"/>
          <el-table-column label="监听" min-width="200" show-overflow-tooltip>
            <template #default="{row}">{{ fmtHostPort(row.listen_addr, row.listen_port) }}</template>
          </el-table-column>
          <el-table-column label="目标" min-width="200" show-overflow-tooltip>
            <template #default="{row}">{{ fmtHostPort(row.target_addr, row.target_port) }}</template>
          </el-table-column>
          <el-table-column label="操作" width="120" fixed="right">
            <template #default="{row}">
              <el-button type="danger" link @click="uDelOne(row)">移除</el-button>
            </template>
          </el-table-column>
        </el-table>

        <div class="panel-footer">
          <el-pagination
            background
            layout="prev, pager, next, ->, total"
            :page-size="uBindSize"
            :current-page="uBindPage"
            :total="uBindTotal"
            @current-change="(p:number)=>{ uBindPage=p; loadUserBindings() }"
          />
        </div>
      </div>

      <!-- 右：候选规则 -->
      <div class="panel">
        <div class="tools-inline">
          <b>选择规则</b>
          <el-select v-model="rQProtocol" placeholder="协议" clearable class="w-120" :teleported="true" popper-class="mb-popper">
            <el-option value="tcp" label="tcp"/>
            <el-option value="udp" label="udp"/>
            <el-option value="socks5" label="socks5"/>
            <el-option value="tls-socks5" label="tls-socks5"/>
            <el-option value="http" label="http"/>
            <el-option value="https" label="https"/>
          </el-select>
          <el-input v-model="rQListenAddr" placeholder="监听IP" clearable class="w-150"/>
          <el-input v-model.number="rQListenPort" placeholder="监听端口" clearable class="w-110"/>
          <el-input v-model="rQTargetAddr" placeholder="目标IP" clearable class="w-150"/>
          <el-input v-model.number="rQTargetPort" placeholder="目标端口" clearable class="w-110"/>
          <el-button @click="rPage=1; loadRuleCandidates()">搜索</el-button>
          <el-button @click="rSelectPage()">全选本页</el-button>
          <el-button @click="rClearSelected()">清空选择</el-button>
        </div>

        <el-table :data="rrule" v-loading="rLoading" height="100%" border>
          <el-table-column label="选" width="60">
            <template #default="{row}">
              <el-checkbox :model-value="rIsSelected(row.id)" @change="rToggleSelect(row)"/>
            </template>
          </el-table-column>
          <el-table-column prop="id" label="ID" width="90"/>
          <el-table-column prop="protocol" label="协议" width="110"/>
          <el-table-column label="监听" min-width="200" show-overflow-tooltip>
            <template #default="{row}">{{ fmtHostPort(row.listen_addr, row.listen_port) }}</template>
          </el-table-column>
          <el-table-column label="目标" min-width="200" show-overflow-tooltip>
            <template #default="{row}">{{ fmtHostPort(row.target_addr, row.target_port) }}</template>
          </el-table-column>
          <el-table-column label="操作" width="120" fixed="right">
            <template #default="{row}">
              <el-button type="primary" link @click="uAddOne(row)">添加</el-button>
            </template>
          </el-table-column>
        </el-table>

        <div class="panel-footer">
          <el-pagination
            background
            layout="prev, pager, next, ->, total"
            :page-size="rSize"
            :current-page="rPage"
            :total="rTotal"
            @current-change="(p:number)=>{ rPage=p; loadRuleCandidates() }"
          />
        </div>

        <div style="margin-top:6px; color:var(--el-text-color-secondary);">
          已选择规则：{{ rSelected.size }} 个
        </div>
      </div>
    </div>

    <template #footer>
      <el-button @click="uDlgVisible=false">关闭</el-button>
      <el-button type="primary" @click="uSaveReplace">
        覆盖保存（保留其作为 OWNER 的规则）
      </el-button>
    </template>
  </el-dialog>
</template>

<style scoped>
/* 工具条：可换行，间距舒适 */
.toolbar{ display:flex; gap:12px; align-items:center; flex-wrap:wrap; }

/* 顶部表格外包一层，手机可横向滚动 */
.table-scroll{ width:100%; overflow-x:auto; }
.minw-1000{ min-width:1000px; }  /* 规则表 */
.minw-800{ min-width:800px; }    /* 用户表 */

/* 分页区 */
.pager{ margin-top:8px; text-align:right; }

/* 弹窗最大宽度不压到侧栏；正文可滚 */
:deep(.binding-dialog .el-dialog){ max-width: calc(100vw - 260px - 24px); }
:deep(.binding-dialog .el-dialog__body){ height: 70vh; padding: 16px 20px; overflow: hidden; }

/* 左右两栏 */
.bindings-grid{
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
  height: 100%;
}
.panel{
  display: grid;
  grid-template-rows: auto 1fr auto;
  min-width: 420px;
  min-height: 0;
}
.panel-footer{
  display:flex; justify-content:flex-end; align-items:center; padding-top:6px;
}

/* 单元格溢出省略（配合 show-overflow-tooltip） */
:deep(.el-table .cell){ white-space:nowrap; text-overflow:ellipsis; overflow:hidden; }

/* peek 文本行内截断 */
.peek{
  display:inline-block; max-width:320px; vertical-align:bottom;
  overflow:hidden; text-overflow:ellipsis; white-space:nowrap;
  color: var(--el-text-color-secondary); margin-left:4px;
}

/* 工具行 */
.tools-inline{ display:flex; gap:8px; align-items:center; margin-bottom:6px; flex-wrap:wrap; }

/* 统一 popper：手机上更宽且不被裁切 */
:deep(.mb-popper.el-popper){ min-width:240px; max-width:90vw; z-index:3000; }

/* 常用宽度工具类（便于自适应覆盖） */
.w-120{width:120px;} .w-110{width:110px;} .w-140{width:140px;} .w-150{width:150px;}
.w-170{width:170px;} .w-180{width:180px;} .w-200{width:200px;} .w-220{width:220px;}
.w-240{width:240px;}

/* 手机（≤600px）：弹窗全屏、两栏变单列、输入控件占满宽 */
@media (max-width: 600px){
  .bindings-grid{ grid-template-columns: 1fr; }
  .panel{ min-width: 0; }
  :deep(.binding-dialog .el-dialog__body){ height: calc(100vh - 120px); }
  .toolbar .w-240, .toolbar .w-220, .toolbar .w-200, .toolbar .w-180,
  .toolbar .w-170, .toolbar .w-150, .toolbar .w-140, .toolbar .w-120, .toolbar .w-110{
    width: 100% !important;
  }
}
</style>
