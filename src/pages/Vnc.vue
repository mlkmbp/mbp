<script setup lang="ts">
import { ref, onMounted, onBeforeUnmount, nextTick } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import api from '../api'
// @ts-ignore
import RFB from '../vendor/novnc/core/rfb.js'

/* ===== 键位 ===== */
const KS = {
  Return: 0xFF0D, Escape: 0xFF1B, BackSpace: 0xFF08, Tab: 0xFF09,
  Left: 0xFF51, Up: 0xFF52, Right: 0xFF53, Down: 0xFF54,
  Home: 0xFF50, End: 0xFF57, PageUp: 0xFF55, PageDown: 0xFF56,
  Insert: 0xFF63, Delete: 0xFFFF,
  F: (n:number)=> 0xFFBD + n,
  CtrlL: 0xFFE3, AltL: 0xFFE9, ShiftL: 0xFFE1,
}
const NUMPAD_MAP: Record<string, number|string> = {
  Numpad0:'0', Numpad1:'1', Numpad2:'2', Numpad3:'3', Numpad4:'4',
  Numpad5:'5', Numpad6:'6', Numpad7:'7', Numpad8:'8', Numpad9:'9',
  NumpadDecimal:'.', NumpadComma:',', NumpadAdd:'+', NumpadSubtract:'-',
  NumpadMultiply:'*', NumpadDivide:'/', NumpadEqual:'=', NumpadEnter: KS.Return,
}

/* ===== 基本状态 ===== */
const route = useRoute()
const vmid = Number(route.params.vmid)
const status = ref('正在连接…')
const screenEl = ref<HTMLElement | null>(null)
let rfb: any = null
let canvasEl: HTMLCanvasElement | null = null

/* ===== 右键菜单 ===== */
const menuOpen = ref(false)
const menuX = ref(0)
const menuY = ref(0)
function openMenu(ev: MouseEvent){ ev.preventDefault(); menuX.value=ev.clientX; menuY.value=ev.clientY; menuOpen.value=true }
function closeMenu(){ menuOpen.value=false }

/* ===== 设备判定（仅手机启用浮钮/IME） ===== */
const isPhone = () => {
  const ua = navigator.userAgent.toLowerCase()
  const phoneUA = /android.*mobile|iphone|ipod/.test(ua)
  return phoneUA && window.innerWidth <= 900
}
const showMobileUI = ref(false)

/* ===== 移动端 IME：隐形输入框 + 浮动按钮（只在手机上） ===== */
const imeEl = ref<HTMLInputElement | null>(null)
const imeOpen = ref(false)   // 我们的“期望状态”，用来切换按钮文案
let composing = false

function wakeIME(){
  const el = imeEl.value
  if (!el) return
  imeOpen.value = true
  el.focus()
  try { el.setSelectionRange(el.value.length, el.value.length) } catch {}
}
function closeIME(){
  const el = imeEl.value
  if (!el) return
  imeOpen.value = false
  try { el.blur() } catch {}
}
function toggleIME(){ imeOpen.value ? closeIME() : wakeIME() }

/* 画布焦点（手机点画布自动收起键盘；PC 则给 canvas 焦点） */
function requestFocus(){
  if (showMobileUI.value && imeOpen.value) closeIME()
  canvasEl = document.querySelector<HTMLCanvasElement>('#vncscreen canvas')
  if (!canvasEl) return
  canvasEl.setAttribute('tabindex','0')
  canvasEl.style.outline = 'none'
  canvasEl.focus()
}

/* ===== 文本发送 / 粘贴（PC 用“上版”策略） ===== */
function sendKeySym(sym: number, downUp:'both'|'down'|'up'='both'){
  try{
    if (downUp !== 'up')  rfb?.sendKey(sym, '', true)
    if (downUp !== 'down')rfb?.sendKey(sym, '', false)
  }catch{}
}
function sendChar(ch: string){ for (const c of [...ch]) sendKeySym(c.codePointAt(0)!) }
function sendAsKeystrokes(s: string){
  for (const ch of s){
    if (ch === '\n') sendKeySym(KS.Return)
    else if (ch === '\t') sendKeySym(KS.Tab)
    else sendChar(ch)
  }
}
function pressCtrl(letter: 'c'|'v'){
  const cp = letter.toUpperCase().codePointAt(0)!
  try{
    rfb?.sendKey(KS.CtrlL,'ControlLeft',true)
    rfb?.sendKey(cp, 'Key'+letter.toUpperCase(), true)
    rfb?.sendKey(cp, 'Key'+letter.toUpperCase(), false)
    rfb?.sendKey(KS.CtrlL,'ControlLeft',false)
  }catch{}
}
function pressCtrlShiftV(){
  try{
    rfb?.sendKey(KS.CtrlL,'ControlLeft',true)
    rfb?.sendKey(KS.ShiftL,'ShiftLeft',true)
    const V='V'.codePointAt(0)!
    rfb?.sendKey(V,'KeyV',true); rfb?.sendKey(V,'KeyV',false)
    rfb?.sendKey(KS.ShiftL,'ShiftLeft',false)
    rfb?.sendKey(KS.CtrlL,'ControlLeft',false)
  }catch{}
}
const hasNonASCII = (s:string)=> /[^\x00-\x7F]/.test(s)
async function smartPasteText(text: string){
  if (!text) return
  // 中文/多行 → 剪贴板 + Ctrl+Shift+V（兜底 Ctrl+V）；纯 ASCII → 逐字符
  if (hasNonASCII(text) || text.includes('\n')){
    try { rfb?.clipboardPasteFrom(text) } catch {}
    pressCtrlShiftV()
    pressCtrl('v')
  }else{
    sendAsKeystrokes(text)
  }
  setTimeout(requestFocus, 0)
}
async function onMenuPaste(){
  try{
    const text = await navigator.clipboard.readText()
    if (!text) return
    await smartPasteText(text)
  }catch{
    ElMessage.info('浏览器限制剪贴板，先粘贴到输入条再发送')
  } finally { closeMenu() }
}

function onMenuFull() {
  closeMenu()
  const root = screenEl.value || document.documentElement
  const doc: any = document
  if (!doc.fullscreenElement) {
    root?.requestFullscreen?.()
  } else {
    doc.exitFullscreen?.()
  }
}

/* ===== IME（移动端中文合成→粘贴；英文→逐字符） ===== */
function onIMECompositionStart(){ composing = true }
function onIMECompositionEnd(){
  composing = false
  const el = imeEl.value!
  const t = el.value
  if (t){
    try { rfb?.clipboardPasteFrom(t) } catch {}
    pressCtrlShiftV()
    pressCtrl('v')
    el.value = ''
  }
}
function onIMEBeforeInput(e: InputEvent){
  if (e.inputType === 'deleteContentBackward'){ e.preventDefault(); sendKeySym(KS.BackSpace) }
  else if (e.inputType === 'insertLineBreak'){ e.preventDefault(); sendKeySym(KS.Return) }
}
function onIMEInput(){
  if (composing) return
  const el = imeEl.value!
  const t = el.value
  if (!t) return
  sendAsKeystrokes(t)
  el.value = ''
}
function onIMEKeydown(e: KeyboardEvent){
  const map: Record<string,number> = {
    Enter:KS.Return, Tab:KS.Tab, Escape:0xFF1B,
    ArrowUp:KS.Up, ArrowDown:KS.Down, ArrowLeft:KS.Left, ArrowRight:KS.Right,
    Home:KS.Home, End:KS.End, PageUp:KS.PageUp, PageDown:KS.PageDown, Delete:KS.Delete,
  }
  if (e.key === 'Backspace'){ e.preventDefault(); sendKeySym(KS.BackSpace); return }
  if (map[e.key]){ e.preventDefault(); sendKeySym(map[e.key]); return }
  if (/^F\d{1,2}$/.test(e.key)){ const n=+e.key.slice(1); if(n>=1&&n<=12){ e.preventDefault(); sendKeySym(0xFFBD+n) } }
}

/* ===== 全局键盘（PC 保持“上版”行为） ===== */
const active = () => document.activeElement === canvasEl || document.activeElement === imeEl.value
function onKeyDown(e: KeyboardEvent){
  if (!rfb) return
  const special = new Set([
    'Home','End','PageUp','PageDown','Insert','Delete',
    'ArrowUp','ArrowDown','ArrowLeft','ArrowRight',
    'NumpadEnter','NumpadAdd','NumpadSubtract','NumpadMultiply','NumpadDivide',
    'NumpadDecimal','NumpadComma','NumpadEqual','Numpad0','Numpad1','Numpad2','Numpad3','Numpad4','Numpad5','Numpad6','Numpad7','Numpad8','Numpad9',
  ])
  if (!active() && !special.has(e.code)) return

  // 智能粘贴（Ctrl/Meta+V 或 Shift+Insert）
  if (((e.ctrlKey||e.metaKey) && e.key.toLowerCase()==='v') || (e.shiftKey && e.code==='Insert')){
    e.preventDefault(); e.stopImmediatePropagation(); onMenuPaste(); return
  }
  // 远端复制（Ctrl+Shift+C / Ctrl+Insert）
  if ((e.ctrlKey && e.shiftKey && e.key.toLowerCase()==='c') || (e.ctrlKey && e.code==='Insert')){
    e.preventDefault(); e.stopImmediatePropagation(); pressCtrl('c'); return
  }

  const table: Record<string,number> = {
    Home:KS.Home, End:KS.End, PageUp:KS.PageUp, PageDown:KS.PageDown, Insert:KS.Insert, Delete:KS.Delete,
    ArrowUp:KS.Up, ArrowDown:KS.Down, ArrowLeft:KS.Left, ArrowRight:KS.Right, Enter:KS.Return,
  }
  if (table[e.key]){ e.preventDefault(); e.stopImmediatePropagation(); sendKeySym(table[e.key],'down'); return }
  if (NUMPAD_MAP[e.code]!==undefined){ e.preventDefault(); e.stopImmediatePropagation(); const v=NUMPAD_MAP[e.code]; if(typeof v==='number') sendKeySym(v,'down'); else sendChar(v as string); return }
  if (/^F\d{1,2}$/.test(e.key)){ const n=+e.key.slice(1); if(n>=1&&n<=12){ e.preventDefault(); e.stopImmediatePropagation(); sendKeySym(0xFFBD+n,'down'); return } }
}
function onKeyUp(e: KeyboardEvent){
  if (!rfb || !active()) return
  const table: Record<string,number> = {
    Home:KS.Home, End:KS.End, PageUp:KS.PageUp, PageDown:KS.PageDown, Insert:KS.Insert, Delete:KS.Delete,
    ArrowUp:KS.Up, ArrowDown:KS.Down, ArrowLeft:KS.Left, ArrowRight:KS.Right, Enter:KS.Return,
  }
  if (table[e.key]){ sendKeySym(table[e.key],'up'); return }
  if (NUMPAD_MAP[e.code]!==undefined){ const v=NUMPAD_MAP[e.code]; if(typeof v==='number') sendKeySym(v,'up'); return }
  if (/^F\d{1,2}$/.test(e.key)){ const n=+e.key.slice(1); if(n>=1&&n<=12){ sendKeySym(0xFFBD+n,'up'); return } }
}

/* ===== 选择复制模式（PC 才有意义） ===== */
const selectCopyMode = ref(false)
function onToggleSelectCopy(){ selectCopyMode.value = !selectCopyMode.value; closeMenu(); ElMessage.success(selectCopyMode.value?'已开启选择复制模式':'已关闭选择复制模式') }
function onScreenMouseUp(){ if (selectCopyMode.value) pressCtrl('c') }

/* 远端剪贴板弹窗 */
let lastClipboardSeen = ''
const clipboardDlg = ref(false)
const clipText = ref('')
const clipArea = ref<HTMLTextAreaElement|null>(null)
function selectClipboardArea(){ const el = clipArea.value; if (el){ el.focus(); el.select() } }
async function copyFromDlg(){
  const text = clipText.value
  try{ await navigator.clipboard.writeText(text); ElMessage.success('已复制到本地剪贴板') }
  catch{ selectClipboardArea(); ElMessage.info('已选中文本，请按 Ctrl+C') }
}
function onRemoteClipboard(e:any){
  const remoteClipboard = e?.detail?.text ?? ''
  clipText.value = remoteClipboard
  if (selectCopyMode.value && remoteClipboard && remoteClipboard !== lastClipboardSeen){
    lastClipboardSeen = remoteClipboard
    clipboardDlg.value = true
    nextTick(selectClipboardArea)
  } else {
    lastClipboardSeen = remoteClipboard
  }
}

/* ===== 连接 ===== */
function proxyWS(url: string){
  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  return `${proto}://${location.host}/ws/pve-vnc?url=${encodeURIComponent(url)}`
}
async function connect(){
  try{
    if (!vmid || Number.isNaN(vmid)) throw new Error('无效 VMID')
    const { data } = await api.post(`/pve/vm/${vmid}/vnc`)
    const wsUrl: string = data?.ws_url
    if (!wsUrl) throw new Error('后端未返回 ws_url')
    const u = new URL(wsUrl)
    const vncTicket = u.searchParams.get('vncticket') || ''
    if (!vncTicket) throw new Error('ws_url 缺少 vncticket')

    const ws = proxyWS(wsUrl)
    const target = screenEl.value!
    rfb = new RFB(target, ws, {
      credentials: { password: vncTicket },
      wsProtocols: ['binary'],
      shared: true,
    })

    // 画质/缩放
    rfb.scaleViewport = true
    rfb.resizeSession = true
    rfb.qualityLevel = 8
    rfb.compressionLevel = 1
    rfb.focusOnClick = true
    rfb.showDotCursor = true

    rfb.addEventListener('credentialsrequired', () => { try{ rfb?.sendCredentials({ password: vncTicket }) }catch{} })
    rfb.addEventListener('connect', async () => {
      status.value='已连接'
      await nextTick()
      requestFocus()
      sendKeySym(KS.Return) // 唤起终端提示
    })
    rfb.addEventListener('disconnect', () => { status.value='已断开' })
    rfb.addEventListener('securityfailure', (e:any)=>{ status.value='安全校验失败'; console.error(e) })
    rfb.addEventListener('clipboard', onRemoteClipboard)
  }catch(e:any){
    // console.error(e)
    // ElMessage.error(e?.message || '连接失败')
    status.value = '连接失败'
  }
}

/* ===== 手机浮动按钮：拖动 + 点击 ===== */
const btnX = ref(0)
const btnY = ref(0)
const dragging = ref(false)
let dragStartX = 0, dragStartY = 0, startBtnX = 0, startBtnY = 0, moved = false
const POS_KEY = 'vnc.kbbtn.pos'
function layoutBtnDefault(){
  const w = window.innerWidth, h = window.innerHeight
  btnX.value = Math.max(8, w - 64 - 12)
  btnY.value = Math.max(8, h - 44 - 12)
}
function clamp(){
  const w = window.innerWidth, h = window.innerHeight
  btnX.value = Math.min(Math.max(8, btnX.value), w - 64 - 8)
  btnY.value = Math.min(Math.max(8, btnY.value), h - 44 - 8)
}
function loadPos(){
  try{
    const raw = localStorage.getItem(POS_KEY)
    if (!raw) return layoutBtnDefault()
    const { x, y } = JSON.parse(raw)
    btnX.value = x ?? 12; btnY.value = y ?? 12; clamp()
  }catch{ layoutBtnDefault() }
}
function savePos(){
  try{ localStorage.setItem(POS_KEY, JSON.stringify({ x: btnX.value, y: btnY.value })) }catch{}
}
function onBtnPointerDown(e: PointerEvent){
  (e.target as HTMLElement).setPointerCapture?.(e.pointerId)
  dragging.value = true; moved = false
  dragStartX = e.clientX; dragStartY = e.clientY
  startBtnX = btnX.value; startBtnY = btnY.value
}
function onBtnPointerMove(e: PointerEvent){
  if (!dragging.value) return
  const dx = e.clientX - dragStartX
  const dy = e.clientY - dragStartY
  if (!moved && Math.hypot(dx,dy) > 6) moved = true
  btnX.value = startBtnX + dx
  btnY.value = startBtnY + dy
  clamp()
}
function onBtnPointerUp(e: PointerEvent){
  (e.target as HTMLElement)?.releasePointerCapture?.(e.pointerId)
  dragging.value = false
  savePos()
  if (!moved) toggleIME() // 点击切换 IME
}

/* ===== 生命周期 ===== */
onMounted(() => {
  showMobileUI.value = isPhone()
  if (showMobileUI.value) {
    loadPos()
    window.addEventListener('pointermove', onBtnPointerMove, true)
    window.addEventListener('pointerup', onBtnPointerUp, true)
    window.addEventListener('resize', () => { clamp(); savePos() })
  }
  document.documentElement.style.overflowX = 'hidden'
  document.body.style.overflowX = 'hidden'
  window.addEventListener('keydown', onKeyDown, true)
  window.addEventListener('keyup', onKeyUp, true)
  window.addEventListener('click', ()=>{ if(menuOpen.value) closeMenu() }, true)
  connect()
})
onBeforeUnmount(() => {
  window.removeEventListener('keydown', onKeyDown, true)
  window.removeEventListener('keyup', onKeyUp, true)
  if (showMobileUI.value) {
    window.removeEventListener('pointermove', onBtnPointerMove, true)
    window.removeEventListener('pointerup', onBtnPointerUp, true)
  }
  try { rfb?.removeEventListener('clipboard', onRemoteClipboard) } catch {}
  document.documentElement.style.overflowX = ''
  document.body.style.overflowX = ''
  try { rfb?.disconnect() } catch {}
})
</script>

<template>
  <div class="vnc-wrap" @contextmenu.prevent>
    <div class="bar">
      <div class="title">
        <span class="dot" :class="status === '已连接' ? 'ok' : 'warn'"></span>
        VNC — VM #{{ vmid }}
      </div>
      <div class="status">{{ status }}</div>
    </div>

    <!-- 移动端隐形 1×1 输入框：仅用于唤醒/关闭输入法；不显示输入条 -->
    <input
      v-if="showMobileUI"
      ref="imeEl"
      class="ime-ghost"
      type="text"
      autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"
      inputmode="text" enterkeyhint="enter"
      @compositionstart="onIMECompositionStart"
      @compositionend="onIMECompositionEnd"
      @beforeinput="onIMEBeforeInput" @input="onIMEInput" @keydown="onIMEKeydown"
    />

    <div
      id="vncscreen"
      class="screen"
      ref="screenEl"
      @pointerdown="requestFocus"
      @mouseup="onScreenMouseUp"
      @touchstart.prevent.stop="requestFocus"
      @contextmenu="openMenu"
    ></div>

    <!-- 手机端：可拖动浮动按钮（点击切换输入法；不显示输入条） -->
    <button
      v-if="showMobileUI"
      class="ime-fab"
      type="button"
      :style="{ left: btnX+'px', top: btnY+'px' }"
      @pointerdown.stop="onBtnPointerDown"
    >
      {{ imeOpen ? '点我收起键盘' : '点画唤醒键盘' }}
    </button>

    <!-- 右键菜单 -->
    <div v-if="menuOpen" class="ctx" :style="{ left: menuX+'px', top: menuY+'px' }" @click.stop>
      <div class="ctx-item" @click="onMenuPaste">粘贴（智能）</div>
      <div v-if="showMobileUI" class="ctx-item" @click="() => { wakeIME(); closeMenu() }">唤醒键盘</div>
      <div class="ctx-sep"></div>
      <div class="ctx-item" @click="() => { closeMenu(); ElMessageBox.confirm('发送 Ctrl + Alt + Del ?', '确认', { type:'warning' }).then(()=>{ try{ rfb?.sendCtrlAltDel() }catch{} }) }">发送 Ctrl + Alt + Del</div>
      <div class="ctx-item" @click="onMenuFull">全屏 / 退出全屏</div>
      <div class="ctx-sep"></div>
      <div v-if="!showMobileUI" class="ctx-item" @click="onToggleSelectCopy">
        {{ selectCopyMode ? '✓ 已开启选择复制模式' : '开启选择复制模式' }}
      </div>
      <div v-if="!showMobileUI" class="ctx-item" @click="clipboardDlg = true">查看/复制 远端剪贴板</div>
    </div>

    <!-- 远端剪贴板对话框（PC 用） -->
    <el-dialog v-model="clipboardDlg" title="远端剪贴板" width="640px">
      <el-input ref="clipArea" v-model="clipText" type="textarea" :rows="8" />
      <template #footer>
        <el-button @click="clipboardDlg=false">关闭</el-button>
        <el-button @click="selectClipboardArea">选中</el-button>
        <el-button type="primary" @click="copyFromDlg">复制到本地</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.vnc-wrap{
  position: fixed; inset: 0;
  background:#0b0b0b; color:#e8e8e8;
  display:flex; flex-direction:column;
  overflow:hidden;
}
.bar{
  display:flex; align-items:center; gap:12px;
  padding:8px 12px; background:#1b1b1b; border-bottom:1px solid #2a2a2a;
}
.title{ font-weight:600; display:flex; align-items:center; gap:8px; }
.dot{ width:8px; height:8px; border-radius:50%; display:inline-block; background:#999; }
.dot.ok{ background:#1ecc6b; box-shadow:0 0 6px #1ecc6b; }
.dot.warn{ background:#f59f00; box-shadow:0 0 6px #f59f00; }
.status{ margin-left:auto; font-size:12px; opacity:.8; }

/* 画布 */
.screen{
  flex:1; overflow:hidden; display:flex; align-items:center; justify-content:center; background:#0b0b0b;
}
.screen :deep(canvas){
  image-rendering:auto;
  max-width:100%; max-height:100%;
  outline:none;
  cursor: default;
}

/* 移动端隐形 1×1 输入框（不可见、可聚焦） */
.ime-ghost{
  position: fixed; bottom: 0; left: 0;
  width: 1px; height: 1px;
  opacity: 0; background: transparent; border: 0; padding: 0; margin: 0;
  z-index: 5; color: transparent; caret-color: transparent;
  pointer-events: none;
}

/* 手机端浮动按钮（可拖动） */
.ime-fab{
  position: fixed; z-index: 11;
  width: 64px; height: 44px;
  background:#2a2b31; color:#e9e9ea; border:1px solid #3a3b41; border-radius:12px;
  font-size:14px; font-weight:600; user-select:none;
  box-shadow: 0 6px 20px rgba(0,0,0,.35);
  touch-action: none;
  cursor: grab;
}
.ime-fab:active{ transform: translateY(1px); }

/* 桌面输入条 */
.deskbar{
  position: fixed; left: 50%; transform: translateX(-50%);
  bottom: 12px; z-index: 22; width: min(820px, 92vw);
  background:#1e1f25; border:1px solid #2c2d33; border-radius:10px; box-shadow: 0 10px 30px rgba(0,0,0,.35);
  padding: 8px;
}
.deskarea{
  width:100%; height:86px; resize:vertical; min-height:60px; max-height:40vh;
  background:#15161a; color:#e9e9ea; border:1px solid #30313a; border-radius:8px;
  padding:8px; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:13px;
  outline:none;
}
.deskbar-actions{ display:flex; justify-content:flex-end; gap:8px; margin-top:6px; }

/* 右键菜单 */
.ctx{
  position: fixed; z-index: 20; min-width: 220px; padding:6px;
  background: #1e1f25; color:#e9e9ea; border:1px solid #2c2d33; border-radius:8px;
  box-shadow: 0 10px 30px rgba(0,0,0,.35);
}
.ctx-item{ padding:6px 10px; border-radius:6px; font-size:13px; user-select:none; }
.ctx-item:hover{ background:#2a2b31; cursor: pointer; }
.ctx-sep{ height:1px; background:#2c2d33; margin:6px 2px; }
</style>
