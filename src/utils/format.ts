// 统一的时间&单位格式化工具

/** 把各种时间输入规整成 'YYYY-MM-DD HH:mm:ss'，无则返回 '-' */
export function formatTime(input?: string | number | Date | null): string {
  if (input === undefined || input === null || input === '') return '-'
  let d: Date | null = null

  if (typeof input === 'number') {
    // 13位时间戳（ms）或10位（s）
    d = new Date(String(input).length === 10 ? input * 1000 : input)
  } else if (typeof input === 'string') {
    // 兼容 RFC3339 / 'YYYY-MM-DD HH:mm:ss'
    const s = input.trim()
    const tryParse = (fmt?: string) => {
      const t = fmt ? new Date(s.replace(' ', 'T')) : new Date(s)
      return isNaN(t.getTime()) ? null : t
    }
    d = tryParse() || tryParse('rfc') // 两次机会
  } else if (input instanceof Date) {
    d = input
  }
  if (!d || isNaN(d.getTime())) return '-'

  const pad = (n: number) => (n < 10 ? '0' + n : '' + n)
  const y = d.getFullYear()
  const M = pad(d.getMonth() + 1)
  const day = pad(d.getDate())
  const h = pad(d.getHours())
  const m = pad(d.getMinutes())
  const s = pad(d.getSeconds())
  return `${y}-${M}-${day} ${h}:${m}:${s}`
}


export function pad2(n: number){ return n<10?('0'+n):(''+n) }