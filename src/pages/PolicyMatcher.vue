<script setup lang="ts">
import { inject, ref, type Ref,  onMounted, onBeforeUnmount, nextTick } from 'vue'
import { ElMessage, ElMessageBox, type FormInstance, type FormRules } from 'element-plus'
import api from '@/api'

const isVmId  = inject<Ref<boolean>>('isVmId', ref(false))
const isAdmin = inject<Ref<boolean>>('isAdmin', ref(false))

type Status = 'enabled' | 'disabled'
type Action = 'direct' | 'forward' | 'reject'
type Kind = 'ip' | 'cidr' | 'domain_exact' | 'domain_suffix' | 'auto'

interface UserLite { id: number; username: string }
interface ForwardLite {
  id: number;
  tag_name: string;
  protocol?: string;
  target_address?: string;
  target_port?: number;
  user_id?: number | null;
}
interface RuleLite { id: number; address: string; port: number; protocol: string }

const ALLOWED = ['http/s', 'tls-http/s', 'socks5', 'tls-socks5']

/* -------------------- 小屏自适应 -------------------- */
const isSmallScreen = ref(typeof window !== 'undefined' ? window.innerWidth <= 600 : false)
function onResize(){ isSmallScreen.value = window.innerWidth <= 600 }
onMounted(()=> window.addEventListener('resize', onResize))
onBeforeUnmount(()=> window.removeEventListener('resize', onResize))

/* -------------------- 入口规则下拉（顶部/表单） -------------------- */
const rulesTop = ref<RuleLite[]>([])
const rulesForm = ref<RuleLite[]>([])

async function fetchRulesTop(userId?: number) {
  const params: any = {}
  if (userId) params.user_id = userId
  const { data } = await api.get('/rule/simple', { params })
  rulesTop.value = (data?.list || []).filter((r: RuleLite) => ALLOWED.includes((r.protocol || '').toLowerCase()))
}
async function fetchRulesForm(userId?: number) {
  const params: any = {}
  if (userId) params.user_id = userId
  const { data } = await api.get('/rule/simple', { params })
  rulesForm.value = (data?.list || []).filter((r: RuleLite) => ALLOWED.includes((r.protocol || '').toLowerCase()))
}

/* -------------------- 用户/转发策略下拉（懒加载） -------------------- */
const users = ref<UserLite[]>([])
async function loadUsersLazy(open: boolean) {
  if (!open || users.value.length) return
  try {
    const { data } = await api.get('/user/simple')
    users.value = data?.list || []
  } catch {}
}

const forwardOpts = ref<ForwardLite[]>([])
async function loadForwardsLazy(open: boolean, userId?: number | null) {
  if (!open) return
  const params: any = { status: 'enabled' }
  if (userId) params.user_id = userId
  const { data } = await api.get('/policy/forward/tag', { params })
  forwardOpts.value = (data?.list || []).map((x: any) => ({
    id: Number(x.id),
    tag_name: String(x.tag_name || ''),
  }))
}

/* -------------------- 列表 & 查询 -------------------- */
const page = ref(1)
const size = ref(10)
const total = ref(0)
const list = ref<any[]>([])

const qKind = ref<Kind | ''>('')           // 匹配类型
const qAction = ref<Action | ''>('')       // 动作
const qRawValue = ref<string>('')          // raw_value 模糊
const qStatus = ref<Status | ''>('')       // 状态
const qMinPri = ref<number | ''>('')       // 最小优先级
const qMaxPri = ref<number | ''>('')       // 最大优先级
const qUserId = ref<number | ''>('')       // 用户ID（管理员可选）
const qFwdId = ref<number | ''>('')        // 绑定的转发策略ID
const qRuleId = ref<number | ''>('')       // 入口规则ID
const qOrder = ref<'priority_asc' | 'priority_desc' | 'time_desc'>('priority_asc')

const ruleMap = ref(new Map<number, RuleLite>())

async function load() {
  const params: any = {
    page: page.value, size: size.value,
    kind: qKind.value || undefined,
    action: qAction.value || undefined,
    raw_value: qRawValue.value || undefined,
    status: qStatus.value || undefined,
    min_priority: qMinPri.value || undefined,
    max_priority: qMaxPri.value || undefined,
    policy_forward_id: qFwdId.value || undefined,
    rule_id: qRuleId.value || undefined,
    order_by: qOrder.value || undefined,
  }
  if (qUserId.value) params.user_id = qUserId.value
  const { data } = await api.get('/policy/matcher', { params })
  list.value = data?.list || []
  total.value = Number(data?.total || 0)

  const m = new Map<number, RuleLite>()
  for (const r of list.value) {
    if (r.rule_id) {
      m.set(Number(r.rule_id), {
        id: Number(r.rule_id),
        address: String(r.rule_address || ''),
        port: Number(r.rule_port || 0),
        protocol: String(r.rule_protocol || ''),
      })
    }
  }
  ruleMap.value = m

  // 翻页后清空选择（只做“全选本页”）
  clearPageSelection()
}

/* -------------------- 新增/编辑（仅改哪个送哪个） -------------------- */
const dialog = ref(false)
const isEdit = ref(false)
const formRef = ref<FormInstance>()

const form = ref({
  id: 0,
  rule_id: null as number | null,
  user_id: null as number | null,          // 仅管理员需选；普通用户后端会覆盖为自己
  kind: '' as Kind | '',
  action: '' as Action | '',
  raw_value: '',
  priority: 100,
  status: 'enabled' as Status,
  policy_forward_id: null as number | null // action=forward 时必选
})

const kindOpts = [
  { label: 'IP', value: 'ip' },
  { label: 'CIDR', value: 'cidr' },
  { label: '全域名(精确)', value: 'domain_exact' },
  { label: '后缀(.example.com)', value: 'domain_suffix' },
] as { label: string; value: Exclude<Kind, 'auto'> | 'auto' }[]

const actionOpts = [
  { label: 'direct 直连', value: 'direct' },
  { label: 'forward 转发', value: 'forward' },
  { label: 'reject 拒绝', value: 'reject' },
] as { label: string; value: Action }[]

const rulesFormRules: FormRules = {
  user_id: [{ required: true, message: '请选择用户', trigger: 'change' }],
  rule_id: [{ required: true, message: '请选择入口规则', trigger: 'change' }],
  kind: [{ required: true, message: '请选择匹配类型', trigger: 'change' }],
  action: [{ required: true, message: '请选择动作', trigger: 'change' }],
  raw_value: [{ required: true, message: '请输入匹配值', trigger: 'blur' }],
  priority: [{ required: true, message: '请输入优先级', trigger: 'blur' }],
  status: [{ required: true, message: '请选择状态', trigger: 'change' }],
  policy_forward_id: [{
    validator: (_r, v, cb) => {
      if (form.value.action === 'forward' && (v == null || v === '')) return cb(new Error('forward 动作需要选择转发策略'))
      cb()
    }, trigger: 'change'
  }]
}

/* -------- 规范化 & 仅发改动 -------- */
function normalizePayload(src: any) {
  const o: any = {}
  o.user_id = src.user_id != null ? Number(src.user_id) : undefined
  o.rule_id = src.rule_id != null ? Number(src.rule_id) : undefined
  o.kind = String(src.kind || '')
  o.action = String(src.action || '')
  o.raw_value = String(src.raw_value || '').trim()
  o.priority = Number(src.priority)
  o.status = String(src.status || 'enabled')
  if (src.action === 'forward') {
    o.policy_forward_id = src.policy_forward_id != null ? Number(src.policy_forward_id) : undefined
  }
  return o
}
function shallowDiff(now: any, old: any) {
  const out: any = {}
  const keys = new Set([...Object.keys(now), ...Object.keys(old || {})])
  keys.forEach(k => {
    const nv = now[k]
    const ov = old?.[k]
    const nvv = typeof nv === 'string' ? nv.trim() : nv
    const ovv = typeof ov === 'string' ? ov?.trim?.() : ov
    if (typeof nvv === 'number' || typeof ovv === 'number') {
      if (Number(nvv) !== Number(ovv)) out[k] = now[k]
    } else if (nvv !== ovv) {
      out[k] = now[k]
    }
  })
  return out
}
const original = ref<any>(null)

/* ---------------- 打开弹窗 ---------------- */
function openCreate() {
  isEdit.value = false
  form.value = {
    id: 0,
    rule_id: null,
    user_id: null,
    kind: '' as any,
    action: '' as any,
    raw_value: '',
    priority: 100,
    status: 'enabled',
    policy_forward_id: null
  }
  original.value = null
  dialog.value = true
}
function openEdit(row: any) {
  isEdit.value = true
  form.value = {
    id: Number(row.id),
    rule_id: Number(row.rule_id || 0) || null,
    user_id: Number(row.user_id || 0) || null,
    kind: String(row.kind) as Kind,
    action: String(row.action) as Action,
    raw_value: String(row.raw_value || ''),
    priority: Number(row.priority || 100),
    status: (row.status || 'enabled') as Status,
    policy_forward_id: row.policy_forward_id != null ? Number(row.policy_forward_id) : null,
  }
  original.value = normalizePayload(form.value)
  dialog.value = true
}

/* ---------------- 提交/删除（单条） ---------------- */
async function submit() {
  const ok = await formRef.value?.validate()
  if (!ok) return

  const normalized = normalizePayload(form.value)
  if (normalized.user_id == null) return ElMessage.error('请选择用户')
  if (normalized.rule_id == null) return ElMessage.error('请选择入口规则')
  if (!normalized.kind) return ElMessage.error('请选择匹配类型')
  if (!normalized.action) return ElMessage.error('请选择动作')
  if (!normalized.raw_value) return ElMessage.error('请输入匹配值')

  if (isEdit.value) {
    const diff = shallowDiff(normalized, original.value || {})
    if (Object.keys(diff).length === 0) {
      ElMessage.info('无改动，无需保存')
      return
    }
    await api.put(`/policy/matcher/${form.value.id}`, diff)
    ElMessage.success('保存成功')
  } else {
    await api.post('/policy/matcher', normalized)
    ElMessage.success('创建成功')
  }
  dialog.value = false
  load()
}
async function confirmDel(id: number) {
  try {
    await ElMessageBox.confirm('确定删除该匹配规则？', '删除确认', { type: 'warning' })
    await api.delete(`/policy/matcher/${id}`)
    ElMessage.success('已删除')
    load()
  } catch {}
}

/* ---------------- 批量新增（保持不变） ---------------- */
const batchDlg = ref(false)
const batchRef = ref<FormInstance>()
const batch = ref({
  user_id: null as number | null,
  rule_id: null as number | null,
  action: '' as Action | '',
  kind: 'auto' as Kind | '',
  status: 'enabled' as Status,
  priority: 100,
  policy_forward_id: null as number | null,
  values: '' // 一行一个；或逗号分隔
})
const batchRules: FormRules = {
  user_id: [{ required: true, message: '请选择用户', trigger: 'change' }],
  rule_id: [{ required: true, message: '请选择入口规则', trigger: 'change' }],
  action: [{ required: true, message: '请选择动作', trigger: 'change' }],
  kind: [{ required: true, message: '请选择匹配类型', trigger: 'change' }],
  status: [{ required: true, message: '请选择状态', trigger: 'change' }],
  priority: [{ required: true, message: '请输入优先级', trigger: 'blur' }],
  policy_forward_id: [{
    validator: (_r, v, cb) => {
      if (batch.value.action === 'forward' && (v == null || v === '')) return cb(new Error('forward 动作需要选择转发策略'))
      cb()
    }, trigger: 'change'
  }],
  values: [{ required: true, message: '请输入匹配值列表', trigger: 'blur' }],
}
function openBatch() {
  batch.value = {
    user_id: null,
    rule_id: null,
    action: '' as any,
    kind: 'auto' as any,
    status: 'enabled',
    priority: 100,
    policy_forward_id: null,
    values: ''
  }
  batchDlg.value = true
}
async function submitBatch() {
  const ok = await batchRef.value?.validate()
  if (!ok) return
  const payload: any = {
    user_id: batch.value.user_id,
    rule_id: batch.value.rule_id,
    action: batch.value.action,
    kind: batch.value.kind,
    status: batch.value.status,
    priority: Number(batch.value.priority),
    policy_forward_id: batch.value.action === 'forward'
      ? (batch.value.policy_forward_id ?? 0)
      : undefined,
    values: batch.value.values,
  }
  try {
    await api.post('/policy/matcher/batch', payload)
    ElMessage.success('批量新增成功')
    batchDlg.value = false
    load()
  } catch (e:any) {
    // ElMessage.error(e?.response?.data?.error || e?.message || '批量新增失败')
  }
}

/* ---------------- 顶部展示辅助 ---------------- */
function getKindLabel(kind: string) {
  const kindOption = kindOpts.find(k => k.value === kind)
  return kindOption ? kindOption.label : kind
}
function getActionLabel(action: string) {
  const actionOption = actionOpts.find(a => a.value === action)
  return actionOption ? actionOption.label : action
}
function fwdLabel(o: ForwardLite) { return `${o.id}#${o.tag_name ?? ''}` }

/* ---------------- 批量删除：全选本页 → 批量删 matcher ---------------- */
// 表格引用 & “当前页已选的 matcher 行 id”
const tableRef = ref<any>()
const selectedRowIds = ref<Set<number>>(new Set())

function onSelectionChange(rows: any[]) {
  const rowSet = new Set<number>()
  for (const r of rows) {
    if (r?.id != null) rowSet.add(Number(r.id))
  }
  selectedRowIds.value = rowSet
}

async function selectAllPage() {
  await nextTick()
  tableRef.value?.clearSelection()
  const rowSet = new Set<number>()
  for (const r of list.value) {
    tableRef.value?.toggleRowSelection(r, true)
    if (r?.id != null) rowSet.add(Number(r.id))
  }
  selectedRowIds.value = rowSet
}

function clearPageSelection() {
  tableRef.value?.clearSelection()
  selectedRowIds.value.clear()
}

async function confirmBulkDelete() {
  const ids = Array.from(selectedRowIds.value)
  if (!ids.length) return ElMessage.info('请先勾选需要删除的记录')
  await ElMessageBox.confirm(
    `将删除本页选中的 ${ids.length} 条匹配规则。确定继续？`,
    '批量删除确认',
    { type: 'warning' }
  )
  // 注意：DELETE 的 body 要放到 axios config.data
  const { data } = await api.delete('/policy/matcher/batch', { data: { ids } })
  const ok = Number(data?.deleted_count ?? 0)
  const forb = (data?.forbidden_ids || []).length
  const nf = (data?.not_found_ids || []).length
  ElMessage.success(`删除完成：成功 ${ok}，无权限 ${forb}，不存在 ${nf}`)
  await load()
  clearPageSelection()
}

/* ---------------- 初始化 ---------------- */
onMounted(async () => { await load() })
</script>

<template>
  <el-card class="pm-card">
    <template #header>
      <div class="toolbar">
        <el-select v-model="qUserId" placeholder="用户(可留空)" clearable filterable class="w-220"
          :teleported="true" popper-class="pm-popper"
          @visible-change="loadUsersLazy">
          <el-option v-for="u in users" :key="u.id" :label="`${u.username} (#${u.id})`" :value="u.id" />
        </el-select>

        <el-select v-model="qRuleId" placeholder="先选用户，再选入口规则(可留空)" clearable filterable class="w-360"
          :disabled="!qUserId" :teleported="true" popper-class="pm-popper"
          @visible-change="(open: boolean) => { if (open) fetchRulesTop(qUserId ? Number(qUserId) : undefined) }">
          <el-option v-for="r in rulesTop" :key="r.id"
            :label="`${r.id} · ${r.address}:${r.port} · ${r.protocol || '-'}`" :value="r.id" />
        </el-select>

        <el-select v-model="qFwdId" :disabled="!qUserId" placeholder="先选用户，再选转发策略(可留空)" clearable filterable class="w-420"
          :teleported="true" popper-class="pm-popper"
          @visible-change="(open: boolean) => loadForwardsLazy(open, qUserId as any)">
          <el-option v-for="f in forwardOpts" :key="f.id" :label="fwdLabel(f)" :value="f.id" />
        </el-select>

        <el-select v-model="qKind" placeholder="匹配类型" clearable class="w-160" :teleported="true" popper-class="pm-popper">
          <el-option v-for="k in kindOpts" :key="k.value" :label="k.label" :value="k.value" />
        </el-select>

        <el-select v-model="qAction" placeholder="动作" clearable class="w-160" :teleported="true" popper-class="pm-popper">
          <el-option v-for="a in actionOpts" :key="a.value" :label="a.label" :value="a.value" />
        </el-select>

        <el-input v-model="qRawValue" placeholder="匹配值(raw_value 模糊)" class="w-220" />
        <el-input v-model.number="qMinPri" placeholder="最小优先级" class="w-130" />
        <el-input v-model.number="qMaxPri" placeholder="最大优先级" class="w-130" />

        <el-select v-model="qStatus" placeholder="状态" clearable class="w-140" :teleported="true" popper-class="pm-popper">
          <el-option label="启用" value="enabled" />
          <el-option label="禁用" value="disabled" />
        </el-select>

        <el-select v-model="qOrder" class="w-180" :teleported="true" popper-class="pm-popper">
          <el-option label="优先级升序" value="priority_asc" />
          <el-option label="优先级降序" value="priority_desc" />
          <el-option label="更新时间降序" value="time_desc" />
        </el-select>

        <div class="toolbar__btns">
          <el-button type="primary" @click="page = 1; load()">查询</el-button>
          <el-button @click="openCreate" v-if="isAdmin || isVmId" >新增</el-button>
          <el-button @click="openBatch" v-if="isAdmin || isVmId" >批量新增</el-button>

          <!-- 批量删除（matcher）：全选本页 / 清除此页 / 批量删除 -->
          <el-button @click="selectAllPage" v-if="isAdmin || isVmId">全选本页</el-button>
          <el-button @click="clearPageSelection" v-if="isAdmin || isVmId">清除此页</el-button>
          <el-button
            type="danger"
            :disabled="selectedRowIds.size === 0"
            @click="confirmBulkDelete"
            v-if="isAdmin || isVmId"
          >
            批量删除匹配规则
            <template v-if="selectedRowIds.size">（{{ selectedRowIds.size }}）</template>
          </el-button>
        </div>
      </div>
    </template>

    <div class="table-scroll">
      <el-table
        ref="tableRef"
        :data="list"
        stripe
        class="pm-table"
        :row-key="(row: { id: string | number }) => row.id"
        @selection-change="onSelectionChange"
      >
        <!-- 选择列 -->
        <el-table-column type="selection" width="44" fixed />

        <el-table-column prop="id" label="ID" width="80" />
        <el-table-column label="用户" min-width="120">
          <template #default="{ row }">
            <span v-if="row.user_id">{{ row.user_id }} # {{ row.username }}</span>
            <span v-else>-</span>
          </template>
        </el-table-column>

        <el-table-column prop="rule_id" label="入口规则ID" width="120" />
        <el-table-column label="入口规则监听" min-width="200">
          <template #default="{ row }">
            <template v-if="row.rule_address">
              {{ row.rule_address }}<template v-if="row.rule_port">:{{ row.rule_port }}</template>
            </template>
            <template v-else>
              {{ ruleMap.get(Number(row.rule_id))?.address || '-' }}
              <template v-if="ruleMap.get(Number(row.rule_id))?.port">:{{ ruleMap.get(Number(row.rule_id))?.port }}</template>
            </template>
          </template>
        </el-table-column>

        <el-table-column label="规则协议" width="140">
          <template #default="{ row }">
            {{ row.rule_protocol || ruleMap.get(Number(row.rule_id))?.protocol || '-' }}
          </template>
        </el-table-column>

        <el-table-column label="匹配类型" min-width="140">
          <template #default="{ row }">
            <span>{{ getKindLabel(row.kind) }}</span>
          </template>
        </el-table-column>

        <el-table-column label="动作" min-width="140">
          <template #default="{ row }">
            <span>{{ getActionLabel(row.action) }}</span>
          </template>
        </el-table-column>

        <el-table-column prop="raw_value" label="匹配值" min-width="260" show-overflow-tooltip />
        <el-table-column prop="priority" label="优先级" width="100" />

        <el-table-column label="转发策略" min-width="160">
          <template #default="{ row }">
            <span v-if="row.policy_forward_id">{{ row.policy_forward_id }} # {{ row.tag_name }}</span>
            <span v-else>-</span>
          </template>
        </el-table-column>

        <el-table-column prop="status" label="状态" width="110">
          <template #default="{ row }">
            <el-tag type="success" v-if="row.status === 'enabled'">启用</el-tag>
            <el-tag type="info" v-else>禁用</el-tag>
          </template>
        </el-table-column>

        <el-table-column label="操作" width="180" fixed="right" v-if="isAdmin || isVmId">
          <template #default="{ row }">
            <el-button size="small" @click="openEdit(row)">编辑</el-button>
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
        @current-change="(p: number) => { page = p; load() }"
      />
    </div>
  </el-card>

  <!-- 新增 / 编辑 -->
  <el-dialog
    v-model="dialog"
    :title="isEdit ? '编辑匹配规则' : '新增匹配规则'"
    :fullscreen="isSmallScreen"
    width="700px"
    destroy-on-close
    class="pm-dialog"
  >
    <el-form ref="formRef" :model="form" :rules="rulesFormRules" label-width="140px" class="pm-form">
      <el-form-item label="用户" prop="user_id">
        <el-select v-model="form.user_id" filterable clearable class="w-320" placeholder="请选择用户"
          :teleported="true" popper-class="pm-popper"
          @visible-change="loadUsersLazy"
          @change="() => { form.policy_forward_id = null; }">
          <el-option v-for="u in users" :key="u.id" :label="`${u.username} (#${u.id})`" :value="u.id" />
        </el-select>
      </el-form-item>

      <el-form-item label="入口规则" prop="rule_id">
        <el-select v-model="form.rule_id" filterable class="w-420" :disabled="!form.user_id"
          placeholder="请选择该用户下 http/s、tls-http/s、socks5、tls-socks5 的规则"
          :teleported="true" popper-class="pm-popper"
          @visible-change="(open: boolean) => { if (open) fetchRulesForm(form.user_id ?? undefined) }">
          <el-option v-for="r in rulesForm" :key="r.id"
            :label="`${r.id} · ${r.address}:${r.port} · ${r.protocol || '-'}`" :value="r.id" />
        </el-select>
      </el-form-item>

      <el-form-item label="匹配类型" prop="kind">
        <el-select v-model="form.kind" class="w-320" :teleported="true" popper-class="pm-popper">
          <el-option v-for="k in kindOpts" :key="k.value" :label="k.label" :value="k.value" />
        </el-select>
      </el-form-item>

      <el-form-item label="动作" prop="action">
        <el-select v-model="form.action" class="w-320" :teleported="true" popper-class="pm-popper">
          <el-option v-for="a in actionOpts" :key="a.value" :label="a.label" :value="a.value" />
        </el-select>
      </el-form-item>

      <el-form-item v-if="form.action === 'forward'" label="转发策略" prop="policy_forward_id">
        <el-select v-model="form.policy_forward_id" :disabled="!form.user_id" filterable clearable class="w-520"
          placeholder="先选用户，再选转发策略"
          :teleported="true" popper-class="pm-popper"
          @visible-change="(open: boolean) => loadForwardsLazy(open, form.user_id)">
          <el-option v-for="f in forwardOpts" :key="f.id" :label="fwdLabel(f)" :value="f.id" />
        </el-select>
      </el-form-item>

      <el-form-item label="匹配值" prop="raw_value">
        <el-input v-model="form.raw_value" placeholder="IP / CIDR / 全域名(example.com) / .后缀(.example.com)" />
      </el-form-item>

      <el-form-item label="优先级" prop="priority">
        <el-input v-model.number="form.priority" placeholder="整数，越小越优先(默认100)" class="w-220" />
      </el-form-item>

      <el-form-item label="状态" prop="status">
        <el-select v-model="form.status" class="w-220" :teleported="true" popper-class="pm-popper">
          <el-option label="启用" value="enabled" />
          <el-option label="禁用" value="disabled" />
        </el-select>
      </el-form-item>
    </el-form>

    <template #footer>
      <el-button @click="dialog = false">取消</el-button>
      <el-button type="primary" @click="submit">保存</el-button>
    </template>
  </el-dialog>

  <!-- 批量新增 -->
  <el-dialog
    v-model="batchDlg"
    title="批量新增匹配规则"
    :fullscreen="isSmallScreen"
    width="760px"
    destroy-on-close
    class="pm-dialog"
  >
    <el-form ref="batchRef" :model="batch" :rules="batchRules" label-width="140px" class="pm-form">
      <el-form-item label="用户" prop="user_id">
        <el-select v-model="batch.user_id" filterable clearable class="w-320" placeholder="请选择用户"
          :teleported="true" popper-class="pm-popper"
          @visible-change="loadUsersLazy"
          @change="() => { batch.policy_forward_id = null; }">
          <el-option v-for="u in users" :key="u.id" :label="`${u.username} (#${u.id})`" :value="u.id" />
        </el-select>
      </el-form-item>

      <el-form-item label="入口规则" prop="rule_id">
        <el-select v-model="batch.rule_id" filterable class="w-420" :disabled="!batch.user_id"
          placeholder="请选择 http/s、tls-http/s、socks5、tls-socks5 的规则"
          :teleported="true" popper-class="pm-popper"
          @visible-change="(open: boolean) => { if (open) fetchRulesForm(batch.user_id ?? undefined) }">
          <el-option v-for="r in rulesForm" :key="r.id"
            :label="`${r.id} · ${r.address}:${r.port} · ${r.protocol || '-'}`" :value="r.id" />
        </el-select>
      </el-form-item>

      <el-form-item label="动作" prop="action">
        <el-select v-model="batch.action" class="w-220" :teleported="true" popper-class="pm-popper">
          <el-option v-for="a in actionOpts" :key="a.value" :label="a.label" :value="a.value" />
        </el-select>
      </el-form-item>

      <el-form-item v-if="batch.action === 'forward'" label="转发策略" prop="policy_forward_id">
        <el-select v-model="batch.policy_forward_id" :disabled="!batch.user_id" filterable clearable class="w-520"
          placeholder="先选用户，再选转发策略"
          :teleported="true" popper-class="pm-popper"
          @visible-change="(open: boolean) => loadForwardsLazy(open, batch.user_id)">
          <el-option v-for="f in forwardOpts" :key="f.id" :label="fwdLabel(f)" :value="f.id" />
        </el-select>
      </el-form-item>

      <el-form-item label="匹配类型" prop="kind">
        <el-select v-model="batch.kind" class="w-320" :teleported="true" popper-class="pm-popper">
          <el-option v-for="k in kindOpts" :key="k.value" :label="k.label" :value="k.value" />
          <el-option label="自动识别" value="auto" />
        </el-select>
      </el-form-item>

      <el-form-item label="优先级" prop="priority">
        <el-input v-model.number="batch.priority" placeholder="整数，默认100" class="w-200" />
      </el-form-item>

      <el-form-item label="状态" prop="status">
        <el-select v-model="batch.status" class="w-200" :teleported="true" popper-class="pm-popper">
          <el-option label="启用" value="enabled" />
          <el-option label="禁用" value="disabled" />
        </el-select>
      </el-form-item>

      <el-form-item label="匹配值列表" prop="values">
        <el-input
          v-model="batch.values"
          type="textarea"
          :rows="10"
          placeholder="一行一个；也可用逗号分隔&#10;IP: 1.2.3.4&#10;CIDR: 10.0.0.0/8&#10;全域名: a.example.com&#10;后缀: .example.com"
        />
      </el-form-item>
    </el-form>

    <template #footer>
      <el-button @click="batchDlg = false">取消</el-button>
      <el-button type="primary" @click="submitBatch">批量保存</el-button>
    </template>
  </el-dialog>
</template>

<style scoped>
/* 圆角卡片 */
.pm-card { border-radius: 14px; }

/* 工具条：可换行 */
.toolbar{ display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
.toolbar__btns{ display:flex; gap:8px; flex-wrap: wrap; }

/* 横向滚动表格容器（小屏不挤爆） */
.table-scroll{ width:100%; overflow-x:auto; }
.pm-table{ min-width: 1200px; }

/* 分页 */
.pager{ margin-top:8px; text-align:right; }

/* 弹窗正文滚动区域（大屏） */
.pm-dialog :deep(.el-dialog__body){ max-height: 70vh; overflow:auto; }

/* 通用宽度工具 */
.w-130{ width:130px; } .w-140{ width:140px; } .w-160{ width:160px; }
.w-180{ width:180px; } .w-200{ width:200px; } .w-220{ width:220px; }
.w-320{ width:320px; } .w-360{ width:360px; } .w-420{ width:420px; }
.w-520{ width:520px; }

/* 下拉 Popper 在手机上不被裁、可更宽 */
:deep(.pm-popper.el-popper){
  min-width: 240px;
  max-width: 90vw;
  z-index: 3000;
}
:deep(.pm-popper .el-select-dropdown__item){
  white-space: nowrap;
}

/* 选中项文本不被裁、行高舒适 */
.pm-form :deep(.el-select .el-select__selected-item){
  line-height: 22px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.pm-form :deep(.el-select .el-input__wrapper){
  min-height: 36px;
  align-items: center;
  box-sizing: border-box;
}

/* 手机（≤600px）：弹窗全屏+控件占满宽 */
@media (max-width: 600px){
  .toolbar .w-220, .toolbar .w-200, .toolbar .w-180, .toolbar .w-160,
  .toolbar .w-140, .toolbar .w-130, .toolbar .w-360, .toolbar .w-420, .toolbar .w-520 {
    width: 100% !important;
  }
  .pm-dialog :deep(.el-dialog__body){ max-height: calc(100vh - 120px); }
  .pm-form :deep(.el-form-item__content){ flex-wrap: wrap; }
  .pm-form :deep(.el-form-item__label){ width: 110px !important; }
  .w-320, .w-420, .w-520 { width: 100% !important; }
}
</style>
