import ApiClient from '@/api/ApiClient.ts'
import type {
    AcmeClientProvider,
    AcmeClientOrder,
    CreateOrderResponse,
    CreateProviderRequest,
    CreateOrderRequest,
} from '@/types/AcmeClient.ts'

export const fetchProviders = async (): Promise<AcmeClientProvider[]> =>
    ApiClient.get<AcmeClientProvider[]>('/acme-client/providers')

export const createProvider = async (req: CreateProviderRequest): Promise<AcmeClientProvider> =>
    ApiClient.post<AcmeClientProvider>('/acme-client/providers', req as Record<string, any>)

export const updateProvider = async (id: number, req: CreateProviderRequest): Promise<AcmeClientProvider> =>
    ApiClient.put<AcmeClientProvider>(`/acme-client/providers/${id}`, req as Record<string, any>)

export const deleteProvider = async (id: number): Promise<void> =>
    ApiClient.delete<void>(`/acme-client/providers/${id}`)

export const fetchOrders = async (): Promise<AcmeClientOrder[]> =>
    ApiClient.get<AcmeClientOrder[]>('/acme-client/orders')

export const createOrder = async (req: CreateOrderRequest): Promise<CreateOrderResponse> =>
    ApiClient.post<CreateOrderResponse>('/acme-client/orders', req as Record<string, any>)

export const issueOrder = async (id: number): Promise<AcmeClientOrder> =>
    ApiClient.post<AcmeClientOrder>(`/acme-client/orders/${id}/issue`, {})

export const deleteOrder = async (id: number): Promise<void> =>
    ApiClient.delete<void>(`/acme-client/orders/${id}`)
