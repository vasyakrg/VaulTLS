export interface TxtRecord {
  name: string
  value: string
}

export interface AcmeClientProvider {
  id: number
  name: string
  directory_url: string
  account_email: string
  eab_kid?: string | null
  created_on: number
}

export interface AcmeClientOrder {
  id: number
  provider_id: number
  domain: string
  include_wildcard: boolean
  status: string
  order_url?: string | null
  txt_records: TxtRecord[]
  cert_id?: number | null
  error?: string | null
  created_on: number
  expires_at?: number | null
}

export interface CreateOrderResponse {
  order_id: number
  txt_records: TxtRecord[]
}

export interface CreateProviderRequest {
  name: string
  directory_url: string
  account_email: string
  eab_kid?: string
  eab_hmac_key?: string
}

export interface CreateOrderRequest {
  provider_id: number
  domain: string
  include_wildcard: boolean
  renews_cert_id?: number | null
}

export interface DnsCheckResult {
  ok: boolean
  expected: string[]
  found: string[]
  missing: string[]
  error: string | null
}
