import { beforeEach, describe, expect, it, vi } from 'vitest'

describe('useSidebar', () => {
  beforeEach(() => {
    document.cookie = 'vaultls_sidebar=; max-age=0'
    vi.resetModules()
  })

  it('defaults to expanded when no cookie', async () => {
    const { useSidebar } = await import('@/composables/useSidebar')
    const { collapsed } = useSidebar()
    expect(collapsed.value).toBe(false)
  })

  it('toggle flips state and writes cookie', async () => {
    const { useSidebar } = await import('@/composables/useSidebar')
    const { collapsed, toggle } = useSidebar()
    toggle()
    expect(collapsed.value).toBe(true)
    expect(document.cookie).toContain('vaultls_sidebar=collapsed')
  })

  it('reads collapsed cookie at init', async () => {
    document.cookie = 'vaultls_sidebar=collapsed'
    const { useSidebar } = await import('@/composables/useSidebar')
    const { collapsed } = useSidebar()
    expect(collapsed.value).toBe(true)
  })
})
