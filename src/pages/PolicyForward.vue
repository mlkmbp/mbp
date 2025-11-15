<script setup lang="ts">
import { inject, ref, type Ref, onMounted, onBeforeUnmount } from 'vue'
import { ElMessage, ElMessageBox, type FormInstance, type FormRules } from 'element-plus'
import api from '@/api'

const isVmId  = inject<Ref<boolean>>('isVmId', ref(false))
const isAdmin = inject<Ref<boolean>>('isAdmin', ref(false))


type Status = 'enabled' | 'disabled'

/* 允许的协议（与后端一致） */
const ALLOWED = ['http/s', 'tls-http/s', 'socks5', 'tls-socks5'] as const
type AllowedProto = typeof ALLOWED[number]

/* ---------------- 用户 ---------------- */
interface UserLite { id: number; username: string }
const users = ref<UserLite[]>([])
const usersLoaded = ref(false)
async function fetchUsers(force = false) {
  if (!force && usersLoaded.value) return
  const { data } = await api.get('/user/simple')
  users.value = data?.list || []
  usersLoaded.value = true
}

/* ---------------- 列表&筛选 ---------------- */
const page = ref(1)
const size = ref(10)
const total = ref(0)
const list = ref<any[]>([])

const qUserId = ref<number | ''>('')   // 用户（可空）
const qProto  = ref<string>('')        // 协议（可空）
const qTagName= ref<string>('')        // 标签名（模糊）
const qStatus = ref<Status | ''>('')   // 状态
const qTAddr  = ref<string>('')        // 上游地址（模糊）

async function load() {
  const params: any = {
    page: page.value,
    size: size.value,
    user_id: qUserId.value || undefined,
    tag_name: qTagName.value || undefined,
    status: qStatus.value || undefined,
    protocol: qProto.value || undefined,
    target_address: qTAddr.value || undefined,
  }
  const { data } = await api.get('/policy/forward', { params })
  list.value  = data?.list || []
  total.value = Number(data?.total || 0)
}

/* ---------------- 表单 ---------------- */
const dialog = ref(false)
const isEdit  = ref(false)
const formRef = ref<FormInstance>()

interface FormModel {
  id: number
  user_id: number | null
  tag_name: string
  protocol: '' | AllowedProto
  target_address: string
  target_port: number | null
  auth_username: string
  auth_password: string  // 编辑时留空=不修改
  skip_cert_verify: boolean
  alpn: string
  tls_fingerprint: string
  tls_sni_guard: string
  status: Status
}

const form = ref<FormModel>({
  id: 0,
  user_id: null,
  tag_name: '',
  protocol: '' as '' | AllowedProto,
  target_address: '',
  target_port: null,
  auth_username: '',
  auth_password: '',
  skip_cert_verify: false,
  alpn: '',
  tls_fingerprint: '',
  tls_sni_guard: '',
  status: 'enabled',
})

/* ---- 仅对必填字段做校验；可选字段允许清空 ---- */
const rulesFormRules: FormRules = {
  user_id: [{ required: true, message: '请选择用户', trigger: 'change' }],
  protocol: [
    { required: true, message: '请选择协议', trigger: 'change' },
    {
      validator: (_r, v: string, cb) => {
        if (!v) return cb(new Error('请选择协议'))
        if (!ALLOWED.includes(v as AllowedProto)) return cb(new Error('不支持的协议'))
        cb()
      }, trigger: 'change'
    }
  ],
  tag_name: [{ required: true, message: '请输入标签名', trigger: 'blur' }],
  target_address: [{ required: true, message: '请输入上游地址', trigger: 'blur' }],
  target_port: [{
    validator: (_r, v, cb) => {
      if (v == null || v === '') return cb(new Error('请输入上游端口'))
      const n = Number(v)
      if (!Number.isInteger(n) || n < 1 || n > 65535) return cb(new Error('端口范围 1~65535'))
      cb()
    }, trigger: 'blur'
  }],
  status: [{ required: true, message: '请选择状态', trigger: 'change' }],
}

/* ---------------- 小屏自适应：弹窗全屏 ---------------- */
const isSmallScreen = ref(typeof window !== 'undefined' ? window.innerWidth <= 600 : false)
function onResize(){ isSmallScreen.value = window.innerWidth <= 600 }
onMounted(()=> window.addEventListener('resize', onResize))
onBeforeUnmount(()=> window.removeEventListener('resize', onResize))

/* ---------------- 规范化（创建 vs 编辑） ---------------- */
/** 创建：只传必填 + 有值的可选（不强制下发空串） */
function normalizeForPost(src: FormModel) {
  const o: any = {}
  o.user_id        = src.user_id != null ? Number(src.user_id) : undefined
  o.tag_name       = String(src.tag_name || '').trim()
  o.protocol       = String(src.protocol || '')
  o.target_address = String(src.target_address || '').trim()
  o.target_port    = src.target_port != null ? Number(src.target_port) : undefined
  o.status         = String(src.status || 'enabled')
  o.skip_cert_verify = !!src.skip_cert_verify

  const putIfFilled = (key: string, val: any) => {
    const v = typeof val === 'string' ? val.trim() : val
    if (v === '' || v == null) return
    o[key] = v
  }
  putIfFilled('auth_username', src.auth_username)
  // 创建：填写了才下发密码
  if (src.auth_password) o.auth_password = String(src.auth_password)
  putIfFilled('alpn', src.alpn)
  putIfFilled('tls_fingerprint', src.tls_fingerprint)
  putIfFilled('tls_sni_guard', src.tls_sni_guard)
  return o
}

/** 编辑：为保证“清空也能下发”，所有可选字符串都参与比较（空字符串也保留） */
function normalizeForDiff(src: FormModel) {
  return {
    user_id:        src.user_id != null ? Number(src.user_id) : undefined,
    tag_name:       String(src.tag_name ?? '').trim(),
    protocol:       String(src.protocol ?? ''),
    target_address: String(src.target_address ?? '').trim(),
    target_port:    src.target_port != null ? Number(src.target_port) : undefined,
    status:         String(src.status ?? 'enabled'),
    skip_cert_verify: !!src.skip_cert_verify,

    // 可选项：全部转成字符串（trim），允许为空串用于“清空”
    auth_username:    String(src.auth_username ?? '').trim(),
    // 密码：保持“编辑时留空=不修改”策略 —— 仅当非空时才参与 diff
    auth_password:    String(src.auth_password ?? ''),
    alpn:             String(src.alpn ?? '').trim(),
    tls_fingerprint:  String(src.tls_fingerprint ?? '').trim(),
    tls_sni_guard:    String(src.tls_sni_guard ?? '').trim(),
  }
}

/** 精确 diff：字符串比较用 trim 后的结果；空串算变化；布尔直接比较；数字按 Number 比较 */
function diffForPut(now: any, old: any) {
  const out: any = {}
  const keys = new Set([...Object.keys(now), ...Object.keys(old || {})])
  keys.forEach(k => {
    // 密码：只有非空时才参与 diff（为空表示“不修改”）
    if (k === 'auth_password') {
      if (now.auth_password !== undefined && now.auth_password !== '') {
        out.auth_password = String(now.auth_password)
      }
      return
    }

    const nv0 = now[k], ov0 = old?.[k]
    // 统一规整
    const isStr = (v: any) => typeof v === 'string' || v instanceof String
    const nv = isStr(nv0) ? String(nv0).trim() : nv0
    const ov = isStr(ov0) ? String(ov0).trim() : ov0

    if (typeof nv === 'number' || typeof ov === 'number') {
      if (Number(nv) !== Number(ov)) out[k] = now[k]
    } else if (typeof nv === 'boolean' || typeof ov === 'boolean') {
      if (Boolean(nv) !== Boolean(ov)) out[k] = now[k]
    } else {
      if (nv !== ov) out[k] = now[k]
    }
  })
  return out
}

/* 原始快照：用于编辑时比较（用 normalizeForDiff 生成） */
const original = ref<any>(null)

/* ---------------- 打开弹窗 ---------------- */
function openCreate() {
  isEdit.value = false
  form.value = {
    id: 0,
    user_id: null,

    tag_name: '',
    protocol: '' as any,
    target_address: '',
    target_port: null,

    auth_username: '',
    auth_password: '', // 创建时：填了才发；不填不发
    skip_cert_verify: false,
    alpn: '',
    tls_fingerprint: '',
    tls_sni_guard: '',

    status: 'enabled',
  }
  original.value = null
  dialog.value = true
}

async function openEdit(row: any) {
  isEdit.value = true
  await fetchUsers()

  form.value = {
    id: Number(row.id),
    user_id: row.user_id != null ? Number(row.user_id) : null,

    tag_name: String(row.tag_name || ''),
    protocol: String(row.protocol || '') as any,
    target_address: String(row.target_address || ''),
    target_port: row.target_port != null ? Number(row.target_port) : null,

    auth_username: String(row.auth_username || ''),
    auth_password: '', // 编辑时留空=不修改（若需清空密码，可输入一个空格再删掉或提供专门的“清空密码”按钮）
    skip_cert_verify: !!row.skip_cert_verify,
    alpn: String(row.alpn || ''),
    tls_fingerprint: String(row.tls_fingerprint || ''),
    tls_sni_guard: String(row.tls_sni_guard || ''),

    status: (row.status || 'enabled') as Status,
  }

  // 记录“完整可 diff 的快照”（注意：密码不会出现在返回中，我们按空串基线）
  original.value = normalizeForDiff(form.value)
  // baseline 的 auth_password 固定为 ''（后端一般不会回传真实密码）
  original.value.auth_password = ''
  dialog.value = true
}

/* ---------------- 提交/删除（错误交给拦截器） ---------------- */
async function submit() {
  const ok = await formRef.value?.validate()
  if (!ok) return

  if (isEdit.value) {
    const nowFull = normalizeForDiff(form.value)
    const diff = diffForPut(nowFull, original.value || {})
    if (Object.keys(diff).length === 0) {
      ElMessage.info('无改动，无需保存')
      return
    }
    await api.put(`/policy/forward/${form.value.id}`, diff)
    ElMessage.success('保存成功')
  } else {
    const payload = normalizeForPost(form.value)
    // 再兜底一次必填
    if (payload.user_id == null) return ElMessage.error('请选择用户')
    if (!payload.protocol)      return ElMessage.error('请选择上游协议')
    if (!payload.tag_name)      return ElMessage.error('请输入标签名')
    if (!payload.target_address)return ElMessage.error('请输入上游地址')
    if (!payload.target_port)   return ElMessage.error('请输入上游端口')

    await api.post('/policy/forward', payload)
    ElMessage.success('创建成功')
  }
  dialog.value = false
  load()
}

async function confirmDel(id: number) {
  try {
    await ElMessageBox.confirm('确定删除该转发策略？', '删除确认', { type: 'warning' })
    await api.delete(`/policy/forward/${id}`)
    ElMessage.success('已删除')
    load()
  } catch { /* 用户取消或拦截器已提示 */ }
}

/* ---------------- 分页 ---------------- */
function onPageChange(p: number) {
  page.value = p
  load()
}

/* ---------------- 初始化 ---------------- */
onMounted(load)
</script>

<template>
  <el-card class="pf-card">
    <template #header>
      <div class="toolbar">
        <el-select
          v-model="qUserId"
          placeholder="用户(可留空)"
          clearable filterable class="w-220"
          @visible-change="(open: boolean) => { if (open) fetchUsers() }"
        >
          <el-option v-for="u in users" :key="u.id" :label="`${u.username} (#${u.id})`" :value="u.id" />
        </el-select>

        <el-input v-model="qTagName" placeholder="标签名" clearable class="w-180" />
        <el-select v-model="qProto" placeholder="上游协议" clearable class="w-150 protocol-trigger">
          <el-option v-for="p in ALLOWED" :key="p" :label="p" :value="p" />
        </el-select>
        <el-input v-model="qTAddr" placeholder="上游地址(模糊)" clearable class="w-200" />
        <el-select v-model="qStatus" placeholder="状态" clearable class="w-140">
          <el-option label="启用" value="enabled" />
          <el-option label="禁用" value="disabled" />
        </el-select>

        <div class="toolbar__btns">
          <el-button type="primary" @click="page = 1; load()">查询</el-button>
          <el-button @click="openCreate" v-if="isAdmin || isVmId" >新增</el-button>
        </div>
      </div>
    </template>

    <div class="table-scroll">
      <el-table :data="list" stripe class="pf-table">
        <el-table-column prop="id" label="ID" width="70" />
        <el-table-column prop="tag_name" label="标签" min-width="140" />
        <el-table-column prop="protocol" label="上游协议" width="120" />
        <el-table-column label="上游目标" min-width="220">
          <template #default="{ row }">
            <span>{{ row.target_address || '-' }}<template v-if="row.target_port">:{{ row.target_port }}</template></span>
          </template>
        </el-table-column>
        <el-table-column prop="auth_username" label="上游用户名" min-width="140" />
        <el-table-column label="证书校验" width="120">
          <template #default="{ row }">
            <el-tag :type="row.skip_cert_verify ? 'warning' : 'success'">
              {{ row.skip_cert_verify ? '跳过校验' : '严格校验' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="alpn" label="ALPN" min-width="120" />
        <el-table-column prop="tls_fingerprint" label="TLS 指纹" min-width="150" />
        <el-table-column prop="tls_sni_guard" label="SNI 白名单" min-width="150" />
        <el-table-column prop="status" label="状态" width="110">
          <template #default="{ row }">
            <el-tag type="success" v-if="row.status === 'enabled'">启用</el-tag>
            <el-tag type="info" v-else>禁用</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="180" fixed="right" v-if="isAdmin || isVmId">
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
    :title="isEdit ? '编辑转发策略' : '新增转发策略'"
    :fullscreen="isSmallScreen"
    width="880px"
    class="pf-dialog"
    destroy-on-close
  >
    <el-form ref="formRef" :model="form" :rules="rulesFormRules" label-width="140px" class="pf-form">

      <!-- 用户：打开下拉才加载一次 -->
      <el-form-item label="用户" prop="user_id">
        <el-select
          v-model="form.user_id"
          filterable class="w-320"
          placeholder="请选择用户"
          :teleported="true"
          @visible-change="(open: boolean) => { if (open) fetchUsers() }"
        >
          <el-option v-for="u in users" :key="u.id" :label="`${u.username} (#${u.id})`" :value="u.id" />
        </el-select>
      </el-form-item>

      <el-form-item label="上游协议" prop="protocol">
        <el-select
          v-model="form.protocol"
          class="w-240"
          :teleported="true"
          :fit-input-width="false"
          placement="bottom-start"
          popper-class="protocol-popper"
          :popper-options="{
            modifiers: [
              { name: 'preventOverflow', options: { padding: 8 } },
              { name: 'flip', options: { fallbackPlacements: ['bottom','top'] } },
              { name: 'computeStyles', options: { adaptive: false } }
            ]
          }"
        >
          <el-option v-for="p in ALLOWED" :key="p" :label="p" :value="p" />
        </el-select>
      </el-form-item>

      <el-form-item label="标签名" prop="tag_name">
        <el-input v-model="form.tag_name" placeholder="例如 netflix / google" />
      </el-form-item>

      <el-form-item label="上游地址/端口">
        <div class="row-inline" style="width:100%;">
          <el-form-item prop="target_address" label-width="0" style="flex:1; margin-bottom:0;">
            <!-- 防浏览器自动填充：autocomplete/new-password + 诱饵字段 -->
            <input type="text" autocomplete="username" style="position:absolute;left:-9999px;opacity:0;height:0;width:0;" />
            <el-input v-model="form.target_address" placeholder="上游地址（域名/IP）" autocomplete="off" />
          </el-form-item>
          <el-form-item prop="target_port" label-width="0" style="width:220px; margin-bottom:0;">
            <el-input v-model.number="form.target_port" type="number" inputmode="numeric" placeholder="端口 1~65535" />
          </el-form-item>
        </div>
      </el-form-item>

      <el-form-item label="上游用户名">
        <input type="text" autocomplete="username" style="position:absolute;left:-9999px;opacity:0;height:0;width:0;" />
        <el-input v-model="form.auth_username" placeholder="留空则不使用基本认证" autocomplete="new-password" />
      </el-form-item>

      <el-form-item label="上游密码">
        <input type="password" autocomplete="new-password" style="position:absolute;left:-9999px;opacity:0;height:0;width:0;" />
        <el-input
          v-model="form.auth_password"
          type="password"
          show-password
          placeholder="编辑时留空=不修改"
          autocomplete="new-password"
        />
      </el-form-item>

      <el-form-item label="跳过证书校验">
        <el-switch v-model="form.skip_cert_verify" />
      </el-form-item>
      <el-form-item label="ALPN">
        <el-input v-model="form.alpn" clearable  placeholder="例如 h2,http/1.1；留空采用默认" />
                  <span class="text-muted ml-8">🥧</span>
      </el-form-item>
      <el-form-item label="TLS 指纹">
        <el-input v-model="form.tls_fingerprint" clearable placeholder="留空采用默认" />
                  <span class="text-muted ml-8">🥧</span>

      </el-form-item>
      <el-form-item label="SNI 白名单">
        <el-input v-model="form.tls_sni_guard" clearable placeholder="逗号分隔；留空不限制" />
      </el-form-item>

      <el-form-item label="状态" prop="status">
        <el-select v-model="form.status" class="w-180" :teleported="true">
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
</template>

<style scoped>
/* ---- 尺寸工具 ---- */
.w-140{ width:140px; } .w-150{ width:150px; } .w-180{ width:180px; }
.w-200{ width:200px; } .w-220{ width:220px; } .w-240{ width:240px; }
.w-320{ width:320px; }

/* ---- 工具条：自适应换行 ---- */
.toolbar{ display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
.toolbar__btns{ display:flex; gap:8px; }

/* ---- 列表横向滚动（小屏不挤爆） ---- */
.table-scroll{ width:100%; overflow-x:auto; }
.pf-table{ min-width: 1100px; }

/* ---- 分页 ---- */
.pager{ margin-top:8px; text-align:right; }

/* ---- 弹窗正文高度（大屏） ---- */
.pf-dialog :deep(.el-dialog__body){ max-height: 70vh; overflow: auto; }

/* ---- 下拉选项不被裁切（协议） ---- */
:deep(.protocol-popper.el-popper){
  min-width: 240px;
  max-width: 90vw;
  z-index: 3000;
}
:deep(.protocol-popper .el-select-dropdown__item){
  white-space: nowrap;
}

/* 选中项文本不被裁、行高正常 */
.pf-form :deep(.el-select .el-select__selected-item){
  line-height: 22px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.pf-form :deep(.el-select .el-input__wrapper){
  min-height: 36px;
  align-items: center;
  box-sizing: border-box;
}

/* ---- 小屏（手机）适配 ---- */
@media (max-width: 600px){
  .toolbar .w-220, .toolbar .w-200, .toolbar .w-180,
  .toolbar .w-150, .toolbar .w-140 { width: 100% !important; }

  .pf-dialog :deep(.el-dialog__body){ max-height: calc(100vh - 120px); }
  .pf-form :deep(.el-form-item__content){ flex-wrap: wrap; }
  .pf-form :deep(.el-form-item__label){ width: 110px !important; }

  .w-320, .w-240 { width: 100% !important; }
}
</style>
