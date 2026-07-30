import { describe, it, expect, vi, beforeEach } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { useCertificateVersionStore } from '@/stores/certificateVersions'
import * as api from '@/api/certificates'

describe('certificateVersions store', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.restoreAllMocks()
  })

  it('loads versions for a certificate', async () => {
    vi.spyOn(api, 'fetchCertificateVersions').mockResolvedValue([
      { version: 2, version_id: null, current: true, created_on: 2, valid_until: 3,
        serial_hex: '0b', fingerprint: 'bb', replaced_at: null, replaced_by: null },
      { version: 1, version_id: 7, current: false, created_on: 0, valid_until: 1,
        serial_hex: '0a', fingerprint: 'aa', replaced_at: 2, replaced_by: 1 },
    ])

    const store = useCertificateVersionStore()
    await store.fetchForCertificate(19)

    expect(store.versions).toHaveLength(2)
    expect(store.versions[0].current).toBe(true)
    expect(store.versions[1].version_id).toBe(7)
    expect(store.error).toBeNull()
  })

  it('records an error when the API refuses', async () => {
    vi.spyOn(api, 'fetchCertificateVersions').mockRejectedValue(new Error('403'))

    const store = useCertificateVersionStore()
    await store.fetchForCertificate(19)

    expect(store.versions).toHaveLength(0)
    expect(store.error).not.toBeNull()
  })
})
