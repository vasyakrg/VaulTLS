export const SERVICE_SCOPES = ['cert:read', 'cert:issue'] as const
export type ServiceScope = (typeof SERVICE_SCOPES)[number]

export interface ServiceAccount {
  id: number
  name: string
  client_id: string
  user_id: number
  scopes: string[]
  created_at: number
  last_used_at: number | null
  revoked: boolean
}

export interface CreateServiceAccountRequest {
  name: string
  scopes: string[]
}

export interface ServiceAccountCreated {
  id: number
  name: string
  client_id: string
  secret: string
  scopes: string[]
}
