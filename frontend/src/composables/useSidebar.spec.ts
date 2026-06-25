import { beforeEach, describe, expect, it } from 'vitest'
import { useSidebar } from '@/composables/useSidebar'

describe('useSidebar', () => {
  beforeEach(() => { document.cookie = 'vaultls_sidebar=; max-age=0' })

  it('defaults to expanded when no cookie', () => {
    const { collapsed } = useSidebar()
    expect(collapsed.value).toBe(false)
  })

  it('toggle flips state and writes cookie', () => {
    const { collapsed, toggle } = useSidebar()
    toggle()
    expect(collapsed.value).toBe(true)
    expect(document.cookie).toContain('vaultls_sidebar=collapsed')
  })

  it('reads collapsed cookie at init', () => {
    document.cookie = 'vaultls_sidebar=collapsed'
    const { collapsed } = useSidebar()
    expect(collapsed.value).toBe(true)
  })
})
