import { describe, expect, it } from 'vitest'
import { validateImportInput } from '@/components/dialogs/importCert'

describe('validateImportInput', () => {
  it('requires user_id', () => {
    expect(validateImportInput({ mode: 'p12', p12: new File([], 'a.p12'), userId: null }))
      .toContain('user_id is required')
  })
  it('p12 mode requires a p12 file', () => {
    expect(validateImportInput({ mode: 'p12', p12: null, userId: 1 })).toContain('p12 file is required')
  })
  it('certkey mode requires cert and key', () => {
    expect(validateImportInput({ mode: 'certkey', cert: new File([], 'c'), key: null, userId: 1 }))
      .toContain('key file is required')
  })
  it('valid p12 input returns no errors', () => {
    expect(validateImportInput({ mode: 'p12', p12: new File([], 'a.p12'), userId: 1 })).toHaveLength(0)
  })
})
