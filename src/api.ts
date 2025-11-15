import axios from 'axios'
import { ElMessage } from 'element-plus'
import type { AxiosRequestHeaders, InternalAxiosRequestConfig } from 'axios'
import router from './router'

// —— 扩展 axios 配置：允许自定义 cfg.silent —— //
declare module 'axios' {
  // 仅用于运行期读取该标记，外部可在请求时传入 config.silent = true
  export interface InternalAxiosRequestConfig<D = any> {
    silent?: boolean
  }
}

const api = axios.create({
  baseURL: '/api',
  timeout: 100000,
})

// 请求拦截：带 token
api.interceptors.request.use(
  (cfg: InternalAxiosRequestConfig) => {
    const token = localStorage.getItem('token')
    if (token) {
      cfg.headers = {
        ...(cfg.headers || {}),
        Authorization: `Bearer ${token}`,
      } as AxiosRequestHeaders
    }
    return cfg
  },
  (error) => Promise.reject(error)
)

let redirecting = false

// 响应拦截：统一错误提示 + 401 处理（支持静默）
api.interceptors.response.use(
  (res) => res,
  async (err) => {
    const status = err?.response?.status
    const cfg: InternalAxiosRequestConfig | undefined = err?.config
    const url = cfg?.url || ''

    // —— 是否静默：三种方式任一满足即静默 —— //
    // 1) config.silent = true
    // 2) 请求头 X-Silent: 1
    // 3) 目标 URL 为 /me（满足“/me 报错不需要提示”的需求）
    const isSilentHeader =
      (cfg?.headers as any)?.['X-Silent'] === '1' ||
      (cfg?.headers as any)?.['x-silent'] === '1'
    const isMeEndpoint = typeof url === 'string' && url.includes('/me')
    const isRestartEndpoint = typeof url === 'string' && url.includes('/restart')
    
    const silent = !!cfg?.silent || !!isSilentHeader || isMeEndpoint || isRestartEndpoint

    // 统一整理错误消息（即使静默也整理，方便上层捕获查看 err.message）
    if (err?.response?.data?.error) {
      err.message = String(err.response.data.error)
    } else if (err?.code === 'ECONNABORTED') {
      err.message = '请求超时，请稍后重试'
    } else if (!err?.response) {
      err.message = '网络异常，请检查网络连接'
    } else {
      err.message =
        err?.response?.data?.message ??
        err?.message ??
        `请求失败（${status || '未知错误'}）`
    }

    // 非静默才弹错误
    if (!silent && err?.message) {
      ElMessage.error(err.message)
    }

    // 仅处理非登录接口的 401（保持原逻辑；静默仅影响“是否弹提示”，不影响跳转）
    if (status === 401 && !url.includes('/login')) {
      const cur = router.currentRoute.value
      if (!redirecting && cur.path !== '/login') {
        redirecting = true
        localStorage.removeItem('token')
        const raw = cur.fullPath || '/'
        const redirect = raw.startsWith('/login') ? '/' : raw
        await router.replace({ path: '/login', query: { redirect } })
        setTimeout(() => {
          redirecting = false
        }, 500)
      }
    }

    return Promise.reject(err)
  }
)

export default api
