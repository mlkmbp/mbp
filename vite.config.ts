// vite.config.ts
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { fileURLToPath, URL } from 'node:url'
import obfuscatorPlugin from 'vite-plugin-javascript-obfuscator'

export default defineConfig({
  plugins: [
    vue(),
    obfuscatorPlugin({
      apply: 'build',
      // 兼容 Windows 路径；仅混淆 src
      include: (id/*: string*/) => id.replace(/\\/g, '/').includes('/src/'),
      options: ({
        rotateUnicodeArray: true,
        compact: true,
        controlFlowFlattening: false,
        controlFlowFlatteningThreshold: 0.8,
        deadCodeInjection: true,
        deadCodeInjectionThreshold: 0.5,
        debugProtection: true,
        debugProtectionInterval: 5000,
        disableConsoleOutput: true,
        domainLock: [],
        identifierNamesGenerator: 'hexadecimal',
        identifiersPrefix: '',
        inputFileName: '',
        log: false,
        renameGlobals: false,
        reservedNames: [],
        reservedStrings: [
          '^@/pages/', '^@/views/', '^@/components/', '^@/layout/', '^@/router/',
          '^/src/pages/', '^/src/views/',
          '^\\./', '^\\.\\./'
        ],
        rotateStringArray: true, 
        seed: 0,
        selfDefending: false,
        sourceMap: false,
        sourceMapBaseUrl: '',
        sourceMapFileName: '',
        sourceMapMode: 'separate',
        stringArray: true,
        stringArrayEncoding: [],
        stringArrayThreshold: 0.8,
        target: 'browser',
        transformObjectKeys: false,
        unicodeEscapeSequence: true,

        // === 兼容新版字段名（有的版本用这两个）===
        stringArrayRotate: true,
        stringArrayShuffle: true
      }) as any
    })
  ],
  server: {
    port: 5173,
    proxy: {
      '/api': { target: 'http://127.0.0.1:14259', changeOrigin: true, ws: true },
      '/ws': { target: 'http://127.0.0.1:14259', changeOrigin: true, ws: true }
    }
  },
  resolve: { alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) } },
  build: { outDir: 'dist', sourcemap: false }
})
