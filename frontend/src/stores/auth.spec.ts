import { describe, expect, it, vi, beforeEach } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { UserRole } from '@/types/User'

const currentUserMock = vi.fn()
const logoutMock = vi.fn()

vi.mock('@/api/auth.ts', () => ({
  current_user: () => currentUserMock(),
  logout: () => logoutMock(),
  login: vi.fn(),
  change_password: vi.fn(),
}))

const { useAuthStore } = await import('@/stores/auth')

const user = {
  id: 1,
  name: 'admin',
  email: 'admin@example.com',
  has_password: true,
  role: UserRole.Admin,
  is_local: true,
}

describe('auth store session handling', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    currentUserMock.mockReset()
    logoutMock.mockReset()
    localStorage.clear()
  })

  it('treats the server as the source of truth on init', async () => {
    currentUserMock.mockResolvedValue(user)
    const store = useAuthStore()
    await store.init()
    expect(store.isAuthenticated).toBe(true)
    expect(store.current_user).toEqual(user)
  })

  it('ignores a stale localStorage flag when the server rejects the cookie', async () => {
    localStorage.setItem('is_authenticated', 'true')
    currentUserMock.mockRejectedValue(new Error('401'))
    const store = useAuthStore()
    await store.init()
    expect(store.isAuthenticated).toBe(false)
    expect(store.current_user).toBeNull()
    expect(localStorage.getItem('is_authenticated')).toBeNull()
  })

  it('verifySession reports the resulting state', async () => {
    const store = useAuthStore()
    currentUserMock.mockResolvedValue(user)
    await expect(store.verifySession()).resolves.toBe(true)
    currentUserMock.mockRejectedValue(new Error('401'))
    await expect(store.verifySession()).resolves.toBe(false)
    expect(store.isAuthenticated).toBe(false)
  })

  it('clears local state even when the logout call fails', async () => {
    currentUserMock.mockResolvedValue(user)
    const store = useAuthStore()
    await store.verifySession()
    expect(store.isAuthenticated).toBe(true)

    logoutMock.mockRejectedValue(new Error('token already expired'))
    await store.logout()
    expect(store.isAuthenticated).toBe(false)
    expect(store.current_user).toBeNull()
  })

  it('clearSession drops state without calling the server', () => {
    const store = useAuthStore()
    store.isAuthenticated = true
    store.current_user = user
    store.clearSession()
    expect(store.isAuthenticated).toBe(false)
    expect(store.current_user).toBeNull()
    expect(logoutMock).not.toHaveBeenCalled()
  })
})
