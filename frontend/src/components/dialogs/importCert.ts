export type ImportInput = {
  mode: 'p12' | 'certkey'
  userId: number | null
  p12?: File | null
  cert?: File | null
  key?: File | null
}

export function validateImportInput(i: ImportInput): string[] {
  const e: string[] = []
  if (i.userId == null) e.push('user_id is required')
  if (i.mode === 'p12' && !i.p12) e.push('p12 file is required')
  if (i.mode === 'certkey') {
    if (!i.cert) e.push('cert file is required')
    if (!i.key) e.push('key file is required')
  }
  return e
}
