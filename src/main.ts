// src/main.ts
import { createApp } from 'vue'
import ElementPlus from 'element-plus'
import 'element-plus/dist/index.css'
import zhCn from 'element-plus/dist/locale/zh-cn.mjs'
import dayjs from 'dayjs'
import 'dayjs/locale/zh-cn'
import 'element-plus/theme-chalk/dark/css-vars.css'


import App from './App.vue'
import router from './router'

dayjs.locale('zh-cn') // ★
createApp(App).use(router).use(ElementPlus, { locale: zhCn }).mount('#app') // ★
