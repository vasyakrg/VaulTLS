import { defineStore } from 'pinia'
import axios from 'axios'
import type { CertificateVersion } from '@/types/CertificateVersion'
import {
  fetchCertificateVersions,
  updateCertificate,
  deleteCertificateVersion,
} from '@/api/certificates'

export const useCertificateVersionStore = defineStore('certificateVersion', {
  state: () => ({
    versions: [] as CertificateVersion[],
    loading: false,
    error: null as string | null,
  }),

  actions: {
    async fetchForCertificate(id: number): Promise<void> {
      this.loading = true
      this.error = null
      try {
        this.versions = await fetchCertificateVersions(id)
      } catch (err) {
        this.versions = []
        this.error = axios.isAxiosError(err)
          ? 'Failed to load certificate versions: ' + err.response?.data?.error
          : 'Failed to load certificate versions'
        console.error(err)
      } finally {
        this.loading = false
      }
    },

    async update(id: number, form: FormData): Promise<boolean> {
      this.loading = true
      this.error = null
      try {
        await updateCertificate(id, form)
        await this.fetchForCertificate(id)
        return true
      } catch (err) {
        this.error = axios.isAxiosError(err)
          ? 'Failed to update certificate: ' + err.response?.data?.error
          : 'Failed to update certificate'
        console.error(err)
        return false
      } finally {
        this.loading = false
      }
    },

    async remove(id: number, version: number): Promise<void> {
      this.loading = true
      this.error = null
      try {
        await deleteCertificateVersion(id, version)
        await this.fetchForCertificate(id)
      } catch (err) {
        this.error = axios.isAxiosError(err)
          ? 'Failed to delete version: ' + err.response?.data?.error
          : 'Failed to delete version'
        console.error(err)
      } finally {
        this.loading = false
      }
    },
  },
})
