import { defineStore } from 'pinia'
import axios from 'axios'
import type {
  ServiceAccount,
  CreateServiceAccountRequest,
  ServiceAccountCreated,
} from '@/types/ServiceAccount'
import {
  listServiceAccounts,
  createServiceAccount,
  revokeServiceAccount,
} from '@/api/serviceAccounts'

export const useServiceAccountStore = defineStore('serviceAccount', {
  state: () => ({
    accounts: [] as ServiceAccount[],
    loading: false,
    error: null as string | null,
    lastCreated: null as ServiceAccountCreated | null,
  }),

  actions: {
    async fetchForUser(userId: number): Promise<void> {
      this.loading = true
      this.error = null
      try {
        this.accounts = await listServiceAccounts(userId)
      } catch (err) {
        this.error = axios.isAxiosError(err)
          ? 'Failed to load service accounts: ' + err.response?.data?.error
          : 'Failed to load service accounts'
        console.error(err)
      } finally {
        this.loading = false
      }
    },

    async create(userId: number, req: CreateServiceAccountRequest): Promise<boolean> {
      this.loading = true
      this.error = null
      try {
        this.lastCreated = await createServiceAccount(userId, req)
        await this.fetchForUser(userId)
        return true
      } catch (err) {
        this.error = axios.isAxiosError(err)
          ? 'Failed to create service account: ' + err.response?.data?.error
          : 'Failed to create service account'
        console.error(err)
        return false
      } finally {
        this.loading = false
      }
    },

    async revoke(userId: number, id: number): Promise<void> {
      this.loading = true
      this.error = null
      try {
        await revokeServiceAccount(id)
        await this.fetchForUser(userId)
      } catch (err) {
        this.error = axios.isAxiosError(err)
          ? 'Failed to revoke service account: ' + err.response?.data?.error
          : 'Failed to revoke service account'
        console.error(err)
      } finally {
        this.loading = false
      }
    },

    clearLastCreated(): void {
      this.lastCreated = null
    },
  },
})
