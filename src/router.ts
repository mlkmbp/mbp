import { createRouter, createWebHistory } from 'vue-router'
import Layout from '@/layout/Layout.vue'
import Login from '@/views/Login.vue'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/login', component: Login, meta: { public: true } },
    
        {
          path: '/vnc/:vmid(\\d+)',
          name: 'vnc',
          component: () => import('./pages/Vnc.vue'),
          props: true,
        },
    {
      path: '/', component: Layout,
      children: [
        { path: '', component: () => import('@/pages/SystemInfo.vue'), meta: { title: '系统信息' } },
        { path: 'systemInfo', component: () => import('@/pages/SystemInfo.vue'), meta: { title: '系统信息' } },
        { path: 'user', component: () => import('@/pages/User.vue'), meta: { title: '用户管理' } },
        { path: 'rule', component: () => import('@/pages/Rule.vue'), meta: { title: '规则管理' } },
        { path: 'mapping', component: () => import('@/pages/Mapping.vue'), meta: { title: '用户-规则映射管理' } },
        { path: 'policyForward', component: () => import('@/pages/PolicyForward.vue'), meta: { title: '转发策略管理' } },
        { path: 'policyMatcher', component: () => import('@/pages/PolicyMatcher.vue'), meta: { title: '转发策略匹配' } },
        { path: 'traffic', component: () => import('@/pages/Traffic.vue'), meta: { title: '流量日志' } },
        { path: 'systemConfig', component: () => import('@/pages/SystemConfig.vue'), meta: { title: '系统配置' } },
        {
          path: '/pve/:vmid(\\d+)',
          name: 'pve',
          component: () => import('@/pages/Pve.vue'),
          props: true
        },
      ],
    },
    { path: '/:pathMatch(.*)*', redirect: '/' },
  ],
})

router.beforeEach((to, _from, next) => {
  // 公开页放行
  if (to.meta.public) return next()

  const token = localStorage.getItem('token') || ''
  if (!token) {
    // 已在登录页就别再跳
    if (to.path === '/login') return next()

    // 不要 encode；并避免把 /login 自己作为 redirect（防止自指循环）
    const raw = to.fullPath || '/'
    const redirect = raw.startsWith('/login') ? '/' : raw
    return next({ path: '/login', query: { redirect } })
  }
  next()
})

export default router
