<script setup lang="ts">
import { ref, computed, onMounted, onBeforeUnmount, nextTick, watch } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import api from '@/api'

const router = useRouter()

/* 登录表单 */
const username = ref(''); const password = ref(''); const loading = ref(false)

/* EULA JSON */
const EULA_JSON_URL = '//mbp.mlkmbp.com/mlkmbp/mlkmbp.json'

/* 数据结构 */
type Slide = { enabled?: boolean; type: 'html' | 'img'; seconds: number; data: string; link?: string }
type EulaPack = { enabled: boolean; date?: string; slides: Slide[]; a?: string }

/* —— 自适配：把阈值调到 768px —— */
const isSmallScreen = ref(false)
const onResize = ()=> (isSmallScreen.value = window.innerWidth <= 768)
onMounted(()=>{ onResize(); window.addEventListener('resize', onResize) })
onBeforeUnmount(()=> window.removeEventListener('resize', onResize))

const showEula = ref(false)
const slides   = ref<Slide[]>([])
const cur      = ref(0)
const secLeft  = ref(0)
let timer: any = null
const packDate = ref<string | undefined>(undefined)
const packA    = ref<string | undefined>(undefined) // 仅随登录携带，不跳 EULA

// 同意勾选
const agreeChecked = ref(false)

/* “欢迎使用”：隐藏的 a 输入框（默认隐藏；点击标题切换） */
const showAField = ref(false)
const aInline    = ref('')
function toggleAField() {
  if (showAField.value) aInline.value = ''
  showAField.value = !showAField.value
}

function stopTimer(){ if (timer){ clearInterval(timer); timer = null } }
function startTimer(s:number){
  stopTimer()
  secLeft.value = Math.max(0, Math.floor(Number(s)||0))
  if (!secLeft.value) return
  timer = setInterval(()=>{
    secLeft.value = Math.max(0, secLeft.value - 1)
    if (!secLeft.value) stopTimer()
  }, 1000)
}
async function enterSlide(i:number){ startTimer(slides.value[i]?.seconds ?? 0); await nextTick() }
function leaveSlide(){ stopTimer() }
const canProceed = computed(()=> secLeft.value <= 0)

async function goPrev(){
  if (cur.value<=0) return
  leaveSlide(); cur.value--; await enterSlide(cur.value)
}
async function goNext(){
  if (!canProceed.value) return
  if (cur.value >= slides.value.length - 1) return
  leaveSlide(); cur.value++; await enterSlide(cur.value)
}
function onDialogClose(){
  showEula.value = false
  stopTimer()
  loading.value = false
}
watch(showEula, v=>{ if (!v) stopTimer() })

/* 拉取 1.json（必须成功；禁缓存） */
async function fetchEulaPackRequired(): Promise<EulaPack>{
  const url = `${EULA_JSON_URL}${EULA_JSON_URL.includes('?') ? '&' : '?'}_ts=${Date.now()}`
  const res = await fetch(url, { mode:'cors', cache:'no-store', credentials:'omit', headers:{ Accept:'application/json' } })
  if (!res.ok) throw new Error(`获取协议失败：HTTP ${res.status}`)
  const raw = await res.json() as any

  const enabledSlides: Slide[] = (raw?.slides || [])
    .filter((s: any) => s && s.enabled !== false)
    .map((s: any) => {
      const t = String(s.type || '').toLowerCase()
      const type: 'html' | 'img' = (t === 'image' || t === 'img') ? 'img' : 'html'
      return { type, seconds: Math.max(0, Math.floor(Number(s.seconds)||0)), data: String(s.data||''), link: s.link } as Slide
    })

  return {
    enabled: !!raw?.enabled,
    date: raw?.date ? String(raw.date) : undefined,
    slides: enabledSlides,
    a: raw?.a ? String(raw.a) : undefined
  }
}

/* 真正登录（支持附加参数） */
async function doLoginAndGoto(extra?: Record<string, any>){
  try{
    const payload: any = { username: username.value, password: password.value, ...(extra || {}) }
    const { data } = await api.post('/login', payload)
    const token = data?.token || ''
    if (!token) throw new Error('登录失败：无 token')
    if(data?.license_message != ""){
      ElMessage.warning(data?.license_message)
    }
    localStorage.setItem('token', token)
    await router.replace('/systemInfo')
  }finally{
    loading.value = false
  }
}

/* 点击登录 */
async function onSubmit(){
  if (!username.value || !password.value){ ElMessage.warning('请输入用户名和密码'); return }

  // 特例：欢迎使用 + 用户手填 a => 直接登录，跳过 EULA
  const aHand = aInline.value.trim()
  if (showAField.value && aHand) {
    loading.value = true
    try{
      await doLoginAndGoto({ a: aHand })
    } finally {
      aInline.value = ''
      showAField.value = false
    }
    return
  }

  // 常规：强制获取 1.json 并弹 EULA（不会因 pack.a 跳过）
  loading.value = true
  agreeChecked.value = false
  try{
    const pack = await fetchEulaPackRequired()
    packDate.value = pack.date
    packA.value    = pack.a // 仅随登录携带

    if (!pack.enabled || pack.slides.length === 0){
      await doLoginAndGoto(packA.value ? { a: packA.value } : undefined)
      return
    }

    slides.value = pack.slides
    cur.value = 0
    showEula.value = true
    await nextTick()
    await enterSlide(cur.value)
  }catch(e:any){
    ElMessage.error('无法获取协议内容，请稍后再试或更新最新版本。')
    loading.value = false
    showAField.value = false
  }
}

/* 最后一页才可同意并登录 */
const isLast = computed(()=> cur.value === slides.value.length - 1)
const canAgreeAndLogin = computed(()=> isLast.value && agreeChecked.value && secLeft.value <= 0)

async function onAgreeAndLogin(){
  if (!canAgreeAndLogin.value) return
  showEula.value = false
  await doLoginAndGoto(packA.value ? { a: packA.value } : undefined)
}

/* 明确拒绝 */
function onReject(){
  showEula.value = false
  loading.value = false
}
</script>

<template>
  <div class="login-container">
    <el-card class="login-card">
      <!-- 头部：点击标题切换隐藏参数 a 输入框（默认隐藏） -->
      <template #header>
        <b class="login-header" @click="toggleAField" title="点击可输入参数 a">欢迎使用</b>
      </template>

      <el-form @submit.prevent="onSubmit" class="login-form">
        <el-form-item label="用户名" :label-width="'80px'">
          <el-input v-model="username" autocomplete="username" placeholder="请输入用户名" />
        </el-form-item>
        <el-form-item label="密码" :label-width="'80px'">
          <el-input v-model="password" type="password" show-password autocomplete="current-password" placeholder="请输入密码" />
        </el-form-item>

        <!-- 隐藏的 a 输入框 -->
        <transition name="fade">
          <div v-if="showAField" class="a-field">
            <el-input v-model="aInline" placeholder="" clearable />
          </div>
        </transition>

        <el-form-item>
          <el-button type="primary" :loading="loading" style="width:100%" @click="onSubmit">登录</el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <!-- EULA 弹窗 -->
    <el-dialog
      v-model="showEula"
      title="用户协议与公告"
      :fullscreen="isSmallScreen"
      width="900px"
      :close-on-click-modal="true"
      :close-on-press-escape="true"
      :show-close="true"
      @close="onDialogClose"
      destroy-on-close
      class="eula-dialog"
    >
      <div class="bar">
        <div class="meta">
          <span v-if="packDate">更新：{{ packDate }}</span>
          <span class="split" />
          <span>本条：{{ slides[cur]?.seconds ?? 0 }}s</span>
          <span class="split" />
          <span>{{ cur+1 }} / {{ slides.length }}</span>
        </div>
        <div class="right" :class="{ok: secLeft<=0}">
          {{ secLeft>0 ? `倒计时 ${secLeft}s` : '可继续' }}
        </div>
      </div>

      <div class="body">
        <!-- HTML -->
        <div v-if="slides[cur]?.type==='html'" class="html-ctn">
          <div class="html-inner" v-html="slides[cur].data"></div>
        </div>

        <!-- 图片 -->
        <div v-else-if="slides[cur]?.type==='img'" class="img-ctn">
          <a v-if="slides[cur]?.link" :href="slides[cur].link" target="_blank" rel="noopener">
            <img :src="slides[cur].data" alt="slide" />
          </a>
          <img v-else :src="slides[cur].data" alt="slide" />
        </div>
      </div>

      <div class="foot">
        <el-button v-if="cur>0" @click="goPrev">上一条</el-button>
        <!-- 最后一页时隐藏 spacer，避免手机端占位 -->
        <div class="spacer" v-show="!isLast" />
        <template v-if="cur < slides.length - 1">
          <el-button type="primary" :disabled="!canProceed" @click="goNext">下一条</el-button>
        </template>

        <!-- 最后一页：PC & Mobile 分开渲染 -->
        <template v-else>
          <!-- 手机端：竖排、全宽 -->
          <div v-if="isSmallScreen" class="agree-wrap-mobile">
            <el-checkbox v-model="agreeChecked" :disabled="!canProceed" class="agree-check-mobile">
              我已阅读并同意以上内容
            </el-checkbox>
            <el-button class="full" @click="onReject">不同意，返回登录</el-button>
            <el-button type="primary" class="full" :disabled="!canAgreeAndLogin" @click="onAgreeAndLogin">
              同意并继续登录
            </el-button>
          </div>

          <!-- 电脑端：横排 -->
          <div v-else class="agree-wrap-desktop">
            <el-checkbox v-model="agreeChecked" :disabled="!canProceed" class="agree-check-desktop">
              我已阅读并同意以上内容
            </el-checkbox>
            <div class="agree-actions-desktop">
              <el-button @click="onReject">不同意，返回登录</el-button>
              <el-button type="primary" :disabled="!canAgreeAndLogin" @click="onAgreeAndLogin">
                同意并继续登录
              </el-button>
            </div>
          </div>
        </template>
      </div>
    </el-dialog>
  </div>
</template>

<style scoped>
/* 登录卡片 */
.login-container{
  display:flex; justify-content:center; align-items:center; height:100vh;
  background: linear-gradient(135deg,#67c23a,#f56c6c);
}
.login-card{ width:400px; box-shadow:0 4px 20px rgba(0,0,0,.1); border-radius:12px; }
.login-header{ display:block; text-align:center; font-size:20px; color:#303133; cursor:pointer; user-select:none; }
.login-form{ padding:20px; }
.el-input,.el-button{ border-radius:8px; }
.el-button{ height:45px; font-size:16px; }

/* 隐藏 a 输入框 */
.a-field{ margin:-2px 0 8px; }
.fade-enter-active, .fade-leave-active{ transition: opacity .18s ease; }
.fade-enter-from, .fade-leave-to{ opacity:0; }

/* 弹窗：PC 70vh；移动端全屏（阈值 768px） */
.eula-dialog :deep(.el-dialog__body){ display:flex; flex-direction:column; height:70vh; }
@media (max-width: 768px){
  .login-card{ width:92vw; }
  .eula-dialog :deep(.el-dialog){ width:100vw !important; height:100vh !important; margin:0 !important; border-radius:0 !important; }
  .eula-dialog :deep(.el-dialog__body){ height: calc(100vh - 54px) !important; padding: 12px !important; }
}

/* 顶部条 */
.bar{ display:flex; align-items:center; margin-bottom:8px; }
.meta{ display:flex; gap:10px; align-items:center; color:#606266; }
.meta .split{ width:1px; height:14px; background:var(--el-border-color); display:inline-block; }
.right{ margin-left:auto; color:#909399; }
.right.ok{ color:#67c23a; }

/* 内容区 */
.body{ flex:1; min-height:0; border:1px solid var(--el-border-color); border-radius:8px; overflow:hidden; background:#fff; }
.html-ctn{ height:100%; overflow:auto; padding:16px; line-height:1.75; color:#303133; }
.html-inner :deep(h1,h2,h3){ margin:10px 0 8px; font-weight:600; }
.html-inner :deep(p){ margin:8px 0; }
.img-ctn{ height:100%; display:flex; align-items:center; justify-content:center; }
.img-ctn img{ width:100%; height:100%; object-fit:contain; }

/* 底部公共 */
.foot{ display:flex; align-items:center; gap:12px; margin-top:10px; flex-wrap:wrap; }
.spacer{ flex:1; }

/* —— 最后一页布局（PC & Mobile 分开） —— */
/* PC：横排 */
.agree-wrap-desktop{
  display:flex; align-items:center; gap:16px; justify-content:flex-end; width:100%;
}
.agree-check-desktop{ flex:1; min-width:240px; line-height:1.6; }
.agree-check-desktop :deep(.el-checkbox__label){ white-space:normal; line-height:1.6; }
.agree-actions-desktop{ display:flex; gap:12px; }
.agree-actions-desktop .el-button{ height:44px; }

/* Mobile：竖排 + 全宽 */
.agree-wrap-mobile{
  width:100%; display:flex; flex-direction:column; gap:10px;
  flex: 1 1 auto;
}
.agree-check-mobile{ width:100%; }
.agree-check-mobile :deep(.el-checkbox__label){ white-space:normal; line-height:1.6; }
.agree-wrap-mobile .full{ width:100%; height:44px; }

/* 兜底：小屏下隐藏 spacer（即使模板忘了 v-show 也不会挤位） */
@media (max-width: 768px){
  .foot .spacer{ display:none !important; }
}
/* 手机端竖排区域把相邻按钮的左间距清零，并保证全宽 */
.agree-wrap-mobile :deep(.el-button){ width:100%; display:block; }
.agree-wrap-mobile :deep(.el-button + .el-button){ margin-left:0 !important; }

</style>
