<script setup lang="ts">
import { ref, watch, onMounted, onBeforeUnmount, provide } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { Monitor, Tickets, UserFilled, Connection, Link as LinkIcon, Filter,Setting } from '@element-plus/icons-vue'
import HeaderBar from '@/components/HeaderBar.vue'
import api from '@/api'

/** ===== 侧栏 / 抽屉状态 ===== */
const collapsed = ref(false)           // 桌面端侧栏折叠
const mobileDrawer = ref(false)        // 手机端抽屉
const isMobile = ref(typeof window !== 'undefined' ? window.innerWidth < 768 : false)

function onResize() {
  if (typeof window === 'undefined') return
  isMobile.value = window.innerWidth < 768
  if (!isMobile.value) mobileDrawer.value = false // 回到桌面端时强制关闭抽屉
}
onMounted(() => window.addEventListener('resize', onResize))
onBeforeUnmount(() => window.removeEventListener('resize', onResize))

/** ===== 路由高亮 & 手机端点击后关闭抽屉 ===== */
const route = useRoute()
const router = useRouter()
const activeIndex = ref(route.path)

watch(
  () => route.path,
  (p) => {
    activeIndex.value = p
    if (isMobile.value) mobileDrawer.value = false  // ★ 路由变化时自动关抽屉（手机）
  },
  { immediate: true }
)

// 手机端：点菜单立即关闭抽屉
function onMenuSelect() {
  if (isMobile.value) mobileDrawer.value = false
}

/** ===== /me 权限决定菜单可见 ===== */
const meLoading = ref(true)
const isAdmin = ref(false)
const isVmId = ref(false)

provide('isAdmin', isAdmin)   // 直接提供 ref，响应式会自动透传
provide('isVmId', isVmId)

async function fetchMeOnce() {
  try {
    const { data } = await api.get('/me')
    isAdmin.value = !!(data?.is_admin)
    if (data?.vm_id <= 0) {
      isVmId.value = true
    }
  } catch {
    isAdmin.value = false
    isVmId.value = false
  } finally {
    meLoading.value = false
    // 非管理员拦截敏感页面
    if (!isAdmin.value && ['/mapping', '/systemConfig'].includes(route.path)) {
      router.replace('/systemInfo')
    }
  }
}
onMounted(fetchMeOnce)
</script>

<template>
  <el-container class="layout">
    <!-- ===== 桌面端侧边栏 ===== -->
    <el-aside v-if="!isMobile" :width="collapsed ? '64px' : '220px'" class="aside">
      <div class="logo" :class="{ center: collapsed }">麻辣烤面包片</div>
      <el-menu router :default-active="activeIndex" :collapse="collapsed" :collapse-transition="false">
        <el-menu-item index="/systemInfo">
          <el-icon>
            <Monitor />
          </el-icon><span>系统信息</span>
        </el-menu-item>

        <el-menu-item index="/user">
          <el-icon>
            <UserFilled />
          </el-icon><span>用户管理</span>
        </el-menu-item>
        <el-menu-item index="/rule">
          <el-icon>
            <Connection />
          </el-icon><span>规则管理</span>
        </el-menu-item>
        <el-menu-item v-if="isAdmin" index="/mapping">
          <el-icon>
            <LinkIcon />
          </el-icon><span>用户-规则映射管理</span>
        </el-menu-item>

        <el-menu-item v-if="isAdmin || isVmId" index="/policyForward">
          <el-icon>
            <Connection />
          </el-icon><span>转发策略管理</span>
        </el-menu-item>
        <el-menu-item v-if="isAdmin || isVmId" index="/policyMatcher">
          <el-icon>
            <Filter />
          </el-icon><span>转发策略匹配</span>
        </el-menu-item>
        <el-menu-item index="/traffic">
          <el-icon>
            <Tickets />
          </el-icon><span>流量日志</span>
        </el-menu-item>
        <el-menu-item v-if="isAdmin" index="/systemConfig">
          <el-icon>
            <Setting />
          </el-icon><span>系统配置</span>
        </el-menu-item>
      </el-menu>
    </el-aside>

    <!-- ===== 手机端抽屉侧边栏 ===== -->
    <el-drawer v-else v-model="mobileDrawer" direction="ltr" :with-header="false" size="220px" class="aside">
      <div class="logo">麻辣烤面包片</div>
      <el-menu router :default-active="activeIndex" @select="onMenuSelect">
        <el-menu-item index="/systemInfo">
          <el-icon>
            <Monitor />
          </el-icon><span>系统信息</span>
        </el-menu-item>

        <el-menu-item index="/user">
          <el-icon>
            <UserFilled />
          </el-icon><span>用户管理</span>
        </el-menu-item>
        <el-menu-item index="/rule">
          <el-icon>
            <Connection />
          </el-icon><span>规则管理</span>
        </el-menu-item>
        <el-menu-item v-if="isAdmin" index="/mapping">
          <el-icon>
            <LinkIcon />
          </el-icon><span>用户-规则映射管理</span>
        </el-menu-item>

        <el-menu-item v-if="isAdmin || isVmId" index="/policyForward">
          <el-icon>
            <Connection />
          </el-icon><span>转发策略管理</span>
        </el-menu-item>
        <el-menu-item v-if="isAdmin || isVmId" index="/policyMatcher">
          <el-icon>
            <Filter />
          </el-icon><span>转发策略匹配</span>
        </el-menu-item>
        <el-menu-item index="/traffic">
          <el-icon>
            <Tickets />
          </el-icon><span>流量日志</span>
        </el-menu-item>
        <el-menu-item v-if="isAdmin" index="/systemConfig">
          <el-icon>
            <Setting />
          </el-icon><span>系统配置</span>
        </el-menu-item>
      </el-menu>
    </el-drawer>

    <!-- ===== 主体区域 ===== -->
    <el-container>
      <!-- Header：高度自适应；按钮事件同时兼容 PC/手机 -->
      <el-header class="app-header">
        <HeaderBar @toggle-aside="isMobile ? (mobileDrawer = !mobileDrawer) : (collapsed = !collapsed)"
          @force-close-aside="isMobile ? (mobileDrawer = false) : (collapsed = true)" />
      </el-header>
      <el-main><router-view /></el-main>
    </el-container>
  </el-container>
</template>

<style scoped>
.layout {
  height: 100vh;
}

/* 侧栏 */
.aside {
  border-right: 1px solid var(--el-border-color);
  background: var(--el-bg-color-overlay);
}

.logo {
  padding: 16px;
  font-weight: 700;
  color: var(--el-text-color-primary);
}

.logo.center {
  text-align: center;
}

/* Header 高度随内容自适应 */
.app-header {
  height: auto;
  flex: 0 0 auto;
  padding: 0;
  border-bottom: none;
}
</style>
