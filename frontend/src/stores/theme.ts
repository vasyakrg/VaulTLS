import { defineStore } from 'pinia'
import { ref, watch } from 'vue'
export type Theme = 'light' | 'dark' | 'auto'

export const useThemeStore = defineStore('theme', () => {
  const theme = ref<Theme>((localStorage.getItem('theme') as Theme) || 'dark')
  const setTheme = (t: Theme) => { theme.value = t; localStorage.setItem('theme', t) }
  const applyTheme = () => {
    const actual = theme.value === 'auto'
      ? (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')
      : theme.value
    document.documentElement.classList.toggle('dark', actual === 'dark')
  }
  watch(theme, applyTheme, { immediate: true })
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
    if (theme.value === 'auto') applyTheme()
  })
  return { theme, setTheme, applyTheme }
})
