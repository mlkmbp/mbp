// src/utils/auth.ts
const KEY = 'token';

export function getToken(): string {
  return localStorage.getItem(KEY) || '';
}

export function setToken(t: string) {
  if (t) localStorage.setItem(KEY, t);
}

export function clearToken() {
  localStorage.removeItem(KEY);
}
