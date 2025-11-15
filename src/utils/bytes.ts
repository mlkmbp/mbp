// 十进制单位（1000）
export type Unit = 'B' | 'KB' | 'MB' | 'GB' | 'TB'

const STEP = 1000
const UNITS: Unit[] = ['B', 'KB', 'MB', 'GB', 'TB']

/** 十进制：把字节数拆成 {value, unit}，单位 B/KB/MB/GB/TB */
export function fromBytesDEC(bytes: number): { value: number; unit: Unit } {
  if (!Number.isFinite(bytes) || bytes <= 0) return { value: 0, unit: 'B' }
  let v = bytes
  let i = 0
  while (v >= STEP && i < UNITS.length - 1) {
    v /= STEP
    i++
  }
  // B 不带小数，其它保留两位
  return { value: +(i === 0 ? Math.round(v) : v.toFixed(2)), unit: UNITS[i] }
}

/** 十进制：格式化 "123 MB" 这种 */
export function formatDEC(bytes: number): string {
  const { value, unit } = fromBytesDEC(bytes)
  return `${value} ${unit}`
}

/* ---------------- 可选：为了无痛替换，保留旧名字 ---------------- */
// 下面两个导出与上面等价，只是沿用原来的名字，内部已经改为 1000 进制
export const fromBytesIEC = fromBytesDEC
export const formatIEC = formatDEC
