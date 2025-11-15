<script setup lang="ts">
import { ref, onMounted, onBeforeUnmount, computed, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import api from '@/api'

/* ---------- Ace（适配 Vite/Esbuild；不要引 webpack-resolver） ---------- */
import { VAceEditor } from 'vue3-ace-editor'
import 'ace-builds/src-noconflict/ace'
import 'ace-builds/src-noconflict/mode-yaml'
import 'ace-builds/src-noconflict/theme-chrome'
import 'ace-builds/src-noconflict/ext-searchbox'

/* ---------- 状态 ---------- */
type Meta = { path: string; mtime: string; etag: string }
const loading    = ref(false)
const restarting = ref(false)
const loaded     = ref(false)

const orig  = ref<string>('')                // 服务器原始内容
const text  = ref<string>('')                // 当前编辑内容
const etag  = ref<string>('')                // 并发保护
const meta  = ref<Meta>({ path:'', mtime:'', etag:'' })

const isSmallScreen = ref(typeof window !== 'undefined' ? window.innerWidth <= 600 : false)
function onResize(){ isSmallScreen.value = window.innerWidth <= 600 }
onMounted(()=> window.addEventListener('resize', onResize))
onBeforeUnmount(()=> window.removeEventListener('resize', onResize))

const dirty = computed(()=> text.value !== orig.value)

/* ---------- 读取 ---------- */
async function load() {
  loading.value = true
  try {
    const { data } = await api.get('/config',{
      headers: { 'Cache-Control': 'no-cache', 'X-Silent': '1' }, // 静默
    })
    orig.value = data?.content ?? ''
    text.value = data?.content ?? ''
    etag.value = data?.etag ?? ''
    meta.value = { path: data?.path ?? '', mtime: data?.mtime ?? '', etag: data?.etag ?? '' }
    loaded.value = true
    // 初次加载就算一次差异
    computeDiff(orig.value, text.value)
    ElMessage.success('已加载配置')
  } catch (e:any) {
    ElMessage.error('读取失败：' + (e?.message || e))
  } finally {
    loading.value = false
  }
}

/* ---------- 简单 Diff（逐行）始终实时显示 ---------- */
type DiffLine = { kind: 'same'|'add'|'del'|'mod', oldLine: number|null, newLine: number|null, text: string }
const diffs = ref<DiffLine[]>([])
const summary = ref({ add:0, del:0, mod:0 })

function computeDiff(a: string, b: string) {
  const A = (a ?? '').replace(/\r\n/g, '\n').split('\n')
  const B = (b ?? '').replace(/\r\n/g, '\n').split('\n')
  const max = Math.max(A.length, B.length)
  const res: DiffLine[] = []
  let adds=0, dels=0, mods=0
  for (let i=0;i<max;i++){
    const l = A[i]; const r = B[i]
    if (l === undefined) { res.push({ kind:'add', oldLine:null, newLine:i+1, text: r ?? '' }); adds++; continue }
    if (r === undefined) { res.push({ kind:'del', oldLine:i+1, newLine:null, text: l ?? '' }); dels++; continue }
    if (l === r) { res.push({ kind:'same', oldLine:i+1, newLine:i+1, text: l }); continue }
    res.push({ kind:'mod', oldLine:i+1, newLine:i+1, text: '旧: '+l+'\n新: '+r }); mods++
  }
  diffs.value = res
  summary.value = { add:adds, del:dels, mod:mods }
}

// 实时：左侧内容或原始内容变化就重算
watch([text, orig], () => computeDiff(orig.value, text.value), { immediate: true })

/* ---------- 保存 / 重启 ---------- */
const showSaveDlg = ref(false)

async function save() {
  if (!dirty.value) return ElMessage.info('无改动，无需保存')
  try {
    loading.value = true
    const { data, status } = await api.put('/config', { content: text.value, etag: etag.value, backup: true },{
      headers: { 'Cache-Control': 'no-cache', 'X-Silent': '1' }, // 静默
    })
    if (status === 200) {
      etag.value = data?.etag || ''
      meta.value.etag = etag.value
      orig.value = text.value
      ElMessage.success('保存成功')
      showSaveDlg.value = false
      await confirmRestart()
    }
  } catch (e:any) {
    if (e?.response?.status === 412) {
      ElMessageBox.alert('配置已被他人修改，请点击“读取”刷新后再试。', '保存失败', { type: 'warning' })
    } else {
      ElMessage.error('保存失败：' + (e?.message || e))
    }
  } finally {
    loading.value = false
  }
}

async function confirmRestart() {
  try {
    await ElMessageBox.confirm('保存已完成，是否现在重启服务以生效？', '重启确认', { type: 'warning' })
    await restart()
  } catch { /* 用户取消 */ }
}

async function restart() {
  try {
    restarting.value = true
    await api.post('/restart')
    ElMessage.success('已触发重启，稍候刷新页面')
  } catch (e:any) {
    ElMessage.error('重启失败：' + (e?.message || e))
  } finally {
    restarting.value = false
  }
}

/* ---------- 初始化 ---------- */
onMounted(load)
</script>

<template>
  <el-card class="cfg-card">
    <template #header>
      <div class="toolbar">
        <div class="title">
          <span>配置编辑器</span>
          <el-tag v-if="loaded" size="small" type="info" class="ml8">{{ meta.path }}</el-tag>
        </div>
        <div class="toolbar__btns">
          <el-button @click="load" :loading="loading">读取</el-button>
          <el-button
            type="primary"
            @click="showSaveDlg = true"
            :disabled="!loaded || !dirty"
          >保存</el-button>
          <el-button type="danger" @click="confirmRestart" :loading="restarting" :disabled="!loaded">重启</el-button>
        </div>
      </div>
    </template>

    <div class="meta" v-if="loaded">
      <span>修改时间：<code>{{ meta.mtime }}</code></span>
      <span class="sep">|</span>
      <span>ETag：<code>{{ meta.etag }}</code></span>
      <span class="sep">|</span>
      <span>改动：<el-tag size="small" type="success">+{{ summary.add }}</el-tag>
                 <el-tag size="small" class="ml4" type="danger">-{{ summary.del }}</el-tag>
                 <el-tag size="small" class="ml4" type="warning">±{{ summary.mod }}</el-tag></span>
    </div>

    <!-- 两栏自适应；不限制高度，跟随内容增长 -->
    <div class="editor-grid" :class="{ stacked: isSmallScreen }">
      <!-- 左：编辑器（YAML 高亮） -->
      <div class="panel">
        <div class="panel-title">编辑内容（YAML）</div>
        <VAceEditor
          v-model:value="text"
          lang="yaml"
          theme="chrome"
          class="ace"
          :options="{
            useWorker: false,          // 关键：禁用 worker，避免动态加载
            showPrintMargin: false,
            tabSize: 2,
            wrap: true,
            highlightActiveLine: true,
            highlightGutterLine: true,
            minLines: 18,
            maxLines: Infinity         // 不限制高度，随行数增长
          }"
        />
      </div>

      <!-- 右：差异预览（实时） -->
      <div class="panel">
        <div class="panel-title">差异预览（实时）</div>
        <div class="diff">
          <div v-if="diffs.length === 0" class="empty">暂无差异</div>
          <div v-else class="diff-lines">
            <div v-for="(d,i) in diffs" :key="i" class="dline" :class="d.kind">
              <div class="ln old" v-if="d.oldLine !== null">{{ d.oldLine }}</div>
              <div class="ln old" v-else></div>
              <div class="ln new" v-if="d.newLine !== null">{{ d.newLine }}</div>
              <div class="ln new" v-else></div>
              <pre class="code">{{ d.text }}</pre>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- 保存确认（展示汇总 + 再次确认） -->
    <el-dialog
      v-model="showSaveDlg"
      :title="'保存确认'"
      :fullscreen="isSmallScreen"
      width="720px"
      destroy-on-close
    >
      <p>即将保存以下改动：</p>
      <ul class="sum">
        <li>新增行：<b>+{{ summary.add }}</b></li>
        <li>删除行：<b>-{{ summary.del }}</b></li>
        <li>修改行：<b>±{{ summary.mod }}</b></li>
      </ul>
      <div class="diff save-diff">
        <div v-if="diffs.length === 0" class="empty">暂无差异</div>
        <div v-else class="diff-lines">
          <div v-for="(d,i) in diffs" :key="'s-'+i" class="dline" :class="d.kind">
            <div class="ln old" v-if="d.oldLine !== null">{{ d.oldLine }}</div>
            <div class="ln old" v-else></div>
            <div class="ln new" v-if="d.newLine !== null">{{ d.newLine }}</div>
            <div class="ln new" v-else></div>
            <pre class="code">{{ d.text }}</pre>
          </div>
        </div>
      </div>
      <template #footer>
        <el-button @click="showSaveDlg = false">取消</el-button>
        <el-button type="primary" @click="save" :loading="loading">确定保存</el-button>
      </template>
    </el-dialog>
  </el-card>
</template>

<style scoped>
/* 不限制整体宽度：撑满容器 */
.cfg-card{ width:100%; }

/* 工具条 */
.toolbar{ display:flex; align-items:center; justify-content:space-between; gap:8px; flex-wrap:wrap; }
.title{ display:flex; align-items:center; gap:8px; font-weight:600; }
.ml8{ margin-left:8px; } .ml4{ margin-left:4px; }
.muted{ color:#999; font-weight:400; }

/* 元信息 */
.meta{ color:#666; font-size:12px; display:flex; gap:8px; margin-bottom:8px; flex-wrap:wrap; }
.meta code{ color:#333; }
.sep{ opacity:.5; }

/* 两栏布局：无固定高度，随内容增长 */
.editor-grid{ display:grid; grid-template-columns: 1fr 1fr; gap:12px; align-items:start; }
.editor-grid.stacked{ grid-template-columns: 1fr; }

/* 面板 */
.panel{ border:1px solid #e5e7eb; border-radius:10px; overflow:hidden; background:#fff; display:flex; flex-direction:column; }
.panel-title{ padding:8px 10px; font-weight:600; border-bottom:1px solid #eef2f7; background:#fafafa; }

/* Ace 外观 */
.ace{ width:100%; }
.ace :deep(.ace_editor){
  width:100%;
  border-top:1px solid #f3f4f6;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size:13px;
}

/* diff（右侧）：无高度限制，随内容增长，如内容多则容器滚动 */
.diff{ overflow:auto; background:#fff; }
.diff-lines{ display:block; }
.dline{
  display:grid; grid-template-columns: 48px 48px 1fr; gap:6px;
  align-items:start; padding:2px 8px; border-bottom:1px dashed #f2f2f2; white-space:pre-wrap;
}
.dline .ln{ color:#999; font-size:12px; text-align:right; }
.dline.same { background:#fff; }
.dline.add  { background:#f6ffed; }
.dline.del  { background:#fff1f0; }
.dline.mod  { background:#fffbe6; }
.code{ margin:0; padding:4px 6px; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:12px; }
.empty{ padding:12px; color:#999; }

/* 保存确认弹窗中 diff（适度限制到视窗，避免弹窗太高） */
.save-diff{ max-height: 60vh; overflow:auto; }

/* 小屏（手机）适配 */
@media (max-width: 600px){
  .editor-grid.stacked .panel{ min-height: 220px; }
}
</style>
