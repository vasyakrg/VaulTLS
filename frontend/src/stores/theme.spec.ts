import { setActivePinia, createPinia } from 'pinia'
import { beforeEach, describe, expect, it } from 'vitest'
import { useThemeStore } from '@/stores/theme'

describe('theme store', () => {
  beforeEach(() => { setActivePinia(createPinia()); document.documentElement.className = '' })

  it('applies dark by adding class "dark"', () => {
    const s = useThemeStore()
    s.setTheme('dark'); s.applyTheme()
    expect(document.documentElement.classList.contains('dark')).toBe(true)
  })

  it('applies light by removing class "dark"', () => {
    const s = useThemeStore()
    s.setTheme('light'); s.applyTheme()
    expect(document.documentElement.classList.contains('dark')).toBe(false)
  })
})
