import { describe, expect, it, vi, beforeEach } from 'vitest'
import type { RouteLocationNormalized } from 'vue-router'

const authState = {
  isAuthenticated: false,
  verifySession: vi.fn(),
  finishOIDC: vi.fn(),
}
const setupState = { isSetup: true }

vi.mock('@/stores/auth', () => ({ useAuthStore: () => authState }))
vi.mock('@/stores/setup', () => ({ useSetupStore: () => setupState }))

const { authGuard } = await import('@/router/authGuard')

const route = (overrides: Partial<RouteLocationNormalized> = {}): RouteLocationNormalized =>
  ({
    name: 'Users',
    fullPath: '/users',
    path: '/users',
    query: {},
    meta: {},
    ...overrides,
  }) as RouteLocationNormalized

describe('authGuard', () => {
  beforeEach(() => {
    authState.isAuthenticated = false
    authState.verifySession = vi.fn().mockResolvedValue(false)
    authState.finishOIDC = vi.fn().mockResolvedValue(undefined)
    setupState.isSetup = true
  })

  it('lets an authenticated user through without re-probing the server', async () => {
    authState.isAuthenticated = true
    await expect(authGuard(route())).resolves.toBe(true)
    expect(authState.verifySession).not.toHaveBeenCalled()
  })

  it('probes the server when no session is on record and allows a valid cookie', async () => {
    authState.verifySession = vi.fn().mockResolvedValue(true)
    await expect(authGuard(route())).resolves.toBe(true)
    expect(authState.verifySession).toHaveBeenCalledOnce()
  })

  it('redirects to login with the target path when the session is dead', async () => {
    await expect(authGuard(route({ fullPath: '/ca' }))).resolves.toEqual({
      name: 'Login',
      query: { redirect: '/ca' },
    })
  })

  // This is the regression that let an expired user keep clicking through tabs: the old
  // `beforeEnter` on the `/` record never ran for child-to-child navigation.
  it('checks every tab, not only the first entry into the layout', async () => {
    for (const path of ['/overview', '/users', '/ca', '/audit']) {
      await expect(authGuard(route({ fullPath: path }))).resolves.toEqual({
        name: 'Login',
        query: { redirect: path },
      })
    }
    expect(authState.verifySession).toHaveBeenCalledTimes(4)
  })

  it('sends an unconfigured instance to first setup', async () => {
    setupState.isSetup = false
    await expect(authGuard(route())).resolves.toEqual({ name: 'FirstSetup' })
  })

  it('does not loop on the first-setup route itself', async () => {
    setupState.isSetup = false
    await expect(authGuard(route({ name: 'FirstSetup', meta: { public: true } }))).resolves.toBe(true)
  })

  it('allows the login page for an anonymous visitor', async () => {
    await expect(authGuard(route({ name: 'Login', meta: { public: true } }))).resolves.toBe(true)
  })

  it('bounces an authenticated user away from the login page', async () => {
    authState.isAuthenticated = true
    await expect(authGuard(route({ name: 'Login', meta: { public: true } }))).resolves.toEqual({
      name: 'Overview',
    })
  })

  it('finishes the OIDC handshake before checking the session', async () => {
    authState.finishOIDC = vi.fn().mockImplementation(async () => {
      authState.isAuthenticated = true
    })
    await expect(authGuard(route({ query: { oidc: 'success' } }))).resolves.toBe(true)
    expect(authState.finishOIDC).toHaveBeenCalledOnce()
  })

  it('falls back to login when the session check throws', async () => {
    authState.verifySession = vi.fn().mockRejectedValue(new Error('network down'))
    vi.spyOn(console, 'error').mockImplementation(() => {})
    await expect(authGuard(route({ fullPath: '/groups' }))).resolves.toEqual({
      name: 'Login',
      query: { redirect: '/groups' },
    })
  })
})
