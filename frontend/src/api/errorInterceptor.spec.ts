import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { AxiosError, AxiosHeaders } from 'axios'
import { handleResponseError } from './errorInterceptor'
import { onSessionExpired } from './sessionExpired'

let clock = Date.parse('2026-01-01T00:00:00Z')

const makeError = (status: number, url: string, data: unknown, statusText = '') => {
  const config = { url, headers: new AxiosHeaders() }
  return new AxiosError('failed', 'ERR', config as never, null, {
    status,
    statusText,
    data,
    headers: new AxiosHeaders(),
    config: config as never,
  })
}

describe('handleResponseError', () => {
  let expired: number

  beforeEach(() => {
    expired = 0
    onSessionExpired(() => {
      expired += 1
    })
    // Each test starts outside the dedup window of the previous one.
    clock += 60_000
    vi.useFakeTimers()
    vi.setSystemTime(clock)
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('fills in a message when the body carries no error field', () => {
    const err = makeError(401, '/certificates', '<html>Unauthorized</html>', 'Unauthorized')
    handleResponseError(err)
    expect(err.response?.data).toEqual({ error: 'Unauthorized' })
  })

  it('falls back to the status code when there is no status text', () => {
    const err = makeError(502, '/certificates', undefined)
    handleResponseError(err)
    expect(err.response?.data).toEqual({ error: 'HTTP 502' })
  })

  it('keeps a server-provided error message', () => {
    const err = makeError(400, '/certificates', { error: 'invalid name' })
    handleResponseError(err)
    expect(err.response?.data).toEqual({ error: 'invalid name' })
  })

  it('leaves a Blob body untouched so download() can parse it', () => {
    const blob = new Blob(['{"error":"nope"}'])
    const err = makeError(404, '/certificates/1/download', blob)
    handleResponseError(err)
    expect(err.response?.data).toBe(blob)
  })

  it('signals session expiry on an unexpected 401', () => {
    handleResponseError(makeError(401, '/certificates', undefined))
    expect(expired).toBe(1)
  })

  it('stays quiet for 401 on the session probe and login endpoints', () => {
    handleResponseError(makeError(401, '/auth/me', undefined))
    handleResponseError(makeError(401, '/auth/login', undefined))
    handleResponseError(makeError(401, '/auth/logout', undefined))
    handleResponseError(makeError(401, '/server/setup', undefined))
    expect(expired).toBe(0)
  })

  it('collapses a burst of 401s into one signal', () => {
    handleResponseError(makeError(401, '/certificates', undefined))
    handleResponseError(makeError(401, '/users', undefined))
    handleResponseError(makeError(401, '/groups', undefined))
    expect(expired).toBe(1)
  })

  it('ignores non-axios errors', () => {
    const err = new Error('boom')
    expect(handleResponseError(err)).toBe(err)
    expect(expired).toBe(0)
  })

  it('ignores network errors that have no response', () => {
    const err = new AxiosError('network', 'ERR_NETWORK')
    expect(handleResponseError(err)).toBe(err)
    expect(expired).toBe(0)
  })
})

describe('notifySessionExpired', () => {
  afterEach(() => {
    vi.useRealTimers()
  })

  it('signals again once the burst window has closed', () => {
    let calls = 0
    onSessionExpired(() => {
      calls += 1
    })
    clock += 60_000
    vi.useFakeTimers()
    vi.setSystemTime(clock)

    handleResponseError(makeError(401, '/certificates', undefined))
    expect(calls).toBe(1)

    // Same window — still one signal.
    vi.setSystemTime(clock + 500)
    handleResponseError(makeError(401, '/certificates', undefined))
    expect(calls).toBe(1)

    // A later expiry in the same page session is reported again.
    vi.setSystemTime(clock + 1500)
    handleResponseError(makeError(401, '/certificates', undefined))
    expect(calls).toBe(2)
  })
})
