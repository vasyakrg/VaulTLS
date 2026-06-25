export type ImportInput = {
  mode: 'p12' | 'certkey'
  userId: number | null
  p12?: File | null
  cert?: File | null
  key?: File | null
}

export function validateImportInput(i: ImportInput): string[] {
  const e: string[] = []
  if (i.userId == null) e.push('userIdRequired')
  if (i.mode === 'p12' && !i.p12) e.push('p12Required')
  if (i.mode === 'certkey') {
    if (!i.cert) e.push('certRequired')
    if (!i.key) e.push('keyRequired')
  }
  return e
}
