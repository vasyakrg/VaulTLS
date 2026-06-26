import ApiClient from './ApiClient'
import type {
  ServiceAccount,
  CreateServiceAccountRequest,
  ServiceAccountCreated,
} from '@/types/ServiceAccount'

export const listServiceAccounts = async (userId: number): Promise<ServiceAccount[]> => {
  return await ApiClient.get<ServiceAccount[]>(`/users/${userId}/service-accounts`)
}

export const createServiceAccount = async (
  userId: number,
  req: CreateServiceAccountRequest,
): Promise<ServiceAccountCreated> => {
  return await ApiClient.post<ServiceAccountCreated>(`/users/${userId}/service-accounts`, req)
}

export const revokeServiceAccount = async (id: number): Promise<void> => {
  await ApiClient.delete<void>(`/service-accounts/${id}`)
}

export const deleteServiceAccount = async (id: number): Promise<void> => {
  await ApiClient.delete<void>(`/service-accounts/${id}/permanent`)
}
