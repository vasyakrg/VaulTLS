import { defineStore } from 'pinia'
import axios from 'axios'
import type {
    AcmeClientProvider,
    AcmeClientOrder,
    CreateOrderResponse,
    CreateProviderRequest,
    CreateOrderRequest,
} from '@/types/AcmeClient.ts'
import * as api from '@/api/acmeClient.ts'

export const useAcmeClientStore = defineStore('acmeClient', {
    state: () => ({
        providers: [] as AcmeClientProvider[],
        orders: [] as AcmeClientOrder[],
        loading: false,
        error: null as string | null,
    }),

    actions: {
        async fetchProviders(): Promise<void> {
            this.error = null
            try {
                this.providers = await api.fetchProviders()
            } catch (err) {
                if (axios.isAxiosError(err)) {
                    this.error = 'Failed to fetch providers: ' + (err.response?.data?.error ?? 'Unknown error')
                } else {
                    this.error = 'Failed to fetch providers'
                }
                console.error(err)
            }
        },

        async fetchOrders(): Promise<void> {
            this.error = null
            try {
                this.orders = await api.fetchOrders()
            } catch (err) {
                if (axios.isAxiosError(err)) {
                    this.error = 'Failed to fetch orders: ' + (err.response?.data?.error ?? 'Unknown error')
                } else {
                    this.error = 'Failed to fetch orders'
                }
                console.error(err)
            }
        },

        async editProvider(id: number, req: CreateProviderRequest): Promise<void> {
            this.loading = true
            this.error = null
            try {
                await api.updateProvider(id, req)
                await this.fetchProviders()
            } catch (err) {
                if (axios.isAxiosError(err)) {
                    this.error = 'Failed to update provider: ' + (err.response?.data?.error ?? 'Unknown error')
                } else {
                    this.error = 'Failed to update provider'
                }
                console.error(err)
                throw err
            } finally {
                this.loading = false
            }
        },

        async addProvider(req: CreateProviderRequest): Promise<void> {
            this.loading = true
            this.error = null
            try {
                await api.createProvider(req)
                await this.fetchProviders()
            } catch (err) {
                if (axios.isAxiosError(err)) {
                    this.error = 'Failed to add provider: ' + (err.response?.data?.error ?? 'Unknown error')
                } else {
                    this.error = 'Failed to add provider'
                }
                console.error(err)
                throw err
            } finally {
                this.loading = false
            }
        },

        async removeProvider(id: number): Promise<void> {
            this.loading = true
            this.error = null
            try {
                await api.deleteProvider(id)
                await this.fetchProviders()
            } catch (err) {
                if (axios.isAxiosError(err)) {
                    this.error = 'Failed to remove provider: ' + (err.response?.data?.error ?? 'Unknown error')
                } else {
                    this.error = 'Failed to remove provider'
                }
                console.error(err)
                throw err
            } finally {
                this.loading = false
            }
        },

        async newOrder(req: CreateOrderRequest): Promise<CreateOrderResponse> {
            this.loading = true
            this.error = null
            try {
                const res = await api.createOrder(req)
                await this.fetchOrders()
                return res
            } catch (err) {
                if (axios.isAxiosError(err)) {
                    this.error = 'Failed to create order: ' + (err.response?.data?.error ?? 'Unknown error')
                } else {
                    this.error = 'Failed to create order'
                }
                console.error(err)
                throw err
            } finally {
                this.loading = false
            }
        },

        async issue(id: number): Promise<void> {
            this.loading = true
            this.error = null
            try {
                await api.issueOrder(id)
                await this.fetchOrders()
            } catch (err) {
                if (axios.isAxiosError(err)) {
                    this.error = 'Failed to issue order: ' + (err.response?.data?.error ?? 'Unknown error')
                } else {
                    this.error = 'Failed to issue order'
                }
                console.error(err)
                throw err
            } finally {
                this.loading = false
            }
        },

        async removeOrder(id: number): Promise<void> {
            this.loading = true
            this.error = null
            try {
                await api.deleteOrder(id)
                await this.fetchOrders()
            } catch (err) {
                if (axios.isAxiosError(err)) {
                    this.error = 'Failed to remove order: ' + (err.response?.data?.error ?? 'Unknown error')
                } else {
                    this.error = 'Failed to remove order'
                }
                console.error(err)
                throw err
            } finally {
                this.loading = false
            }
        },
    },
})
