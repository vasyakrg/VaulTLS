<template>
  <BaseModal
    :visible="visible"
    :title="$t('certVersions.historyTitle')"
    hideFooter
    width="720px"
    @update:visible="(v: boolean) => emit('update:visible', v)"
    @cancel="emit('update:visible', false)"
  >
    <DataTable :value="store.versions" :loading="store.loading" dataKey="version" class="vt-table">
      <Column field="version" :header="$t('certVersions.version')">
        <template #body="{ data }">
          <span class="vt-version-cell">
            {{ data.version }}
            <Tag v-if="data.current" :value="$t('certVersions.current')" severity="success" />
          </span>
        </template>
      </Column>
      <Column :header="$t('common.colCreatedOn')">
        <template #body="{ data }">{{ formatDate(data.created_on) }}</template>
      </Column>
      <Column :header="$t('common.colValidUntil')">
        <template #body="{ data }">{{ formatDate(data.valid_until) }}</template>
      </Column>
      <Column :header="$t('certVersions.fingerprint')">
        <template #body="{ data }">
          <code v-tooltip.top="data.fingerprint ?? ''">{{ short(data.fingerprint) }}</code>
        </template>
      </Column>
      <Column :header="$t('certVersions.replacedAt')">
        <template #body="{ data }">{{ data.replaced_at ? formatDate(data.replaced_at) : '—' }}</template>
      </Column>
      <Column :header="$t('common.actions')">
        <template #body="{ data }">
          <div class="vt-row-actions">
            <Button
              icon="pi pi-download"
              severity="secondary"
              outlined
              size="small"
              v-tooltip.top="$t('certVersions.downloadP12')"
              :aria-label="$t('certVersions.downloadP12')"
              @click="download(data.version)"
            />
            <Button
              icon="pi pi-file-export"
              severity="secondary"
              outlined
              size="small"
              v-tooltip.top="$t('certVersions.downloadPem')"
              :aria-label="$t('certVersions.downloadPem')"
              @click="download(data.version, 'pem')"
            />
            <Button
              icon="pi pi-key"
              severity="secondary"
              outlined
              size="small"
              v-tooltip.top="$t('certVersions.showPassword')"
              :aria-label="$t('certVersions.showPassword')"
              @click="showPassword(data.version)"
            />
            <Button
              v-if="authStore.isLocalAdmin && !data.current"
              icon="pi pi-trash"
              severity="danger"
              outlined
              size="small"
              :disabled="store.loading"
              v-tooltip.top="$t('certVersions.deleteVersion')"
              :aria-label="$t('certVersions.deleteVersion')"
              @click="remove(data.version)"
            />
          </div>
        </template>
      </Column>
      <template #empty>
        <div class="vt-empty">{{ $t('certVersions.noHistory') }}</div>
      </template>
    </DataTable>

    <div v-if="revealed" class="vt-secret">
      <span class="vt-mono">{{ $t('certVersions.showPassword') }}:</span>
      <code>{{ revealed }}</code>
    </div>
    <div v-if="localError" class="vt-error">{{ localError }}</div>
    <div v-if="store.error" class="vt-error">{{ store.error }}</div>
  </BaseModal>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import Tooltip from 'primevue/tooltip'
import BaseModal from '@/components/BaseModal.vue'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Tag from 'primevue/tag'
import Button from 'primevue/button'
import { useCertificateVersionStore } from '@/stores/certificateVersions'
import { useAuthStore } from '@/stores/auth'
import { downloadCertificate, fetchCertificatePassword } from '@/api/certificates'
import type { Certificate } from '@/types/Certificate'

const props = defineProps<{ visible: boolean; certificate: Certificate | null }>()
const emit = defineEmits<{ 'update:visible': [boolean] }>()

const vTooltip = Tooltip
const { t } = useI18n()

const store = useCertificateVersionStore()
const authStore = useAuthStore()

// Secret material: never logged, always cleared as soon as the dialog is opened or closed.
const revealed = ref<string | null>(null)
const localError = ref<string | null>(null)

watch(
  () => props.visible,
  (open) => {
    revealed.value = null
    localError.value = null
    if (open && props.certificate) store.fetchForCertificate(props.certificate.id)
  },
)

const short = (fp: string | null) => (fp ? `${fp.slice(0, 12)}…` : '—')
const formatDate = (ms: number) => new Date(ms).toLocaleString()

const download = async (version: number, format?: 'pem') => {
  if (!props.certificate) return
  localError.value = null
  try {
    await downloadCertificate(props.certificate.id, format, version)
  } catch {
    localError.value = t('certVersions.downloadFailed') // no secret material in this path
  }
}

const showPassword = async (version: number) => {
  if (!props.certificate) return
  localError.value = null
  revealed.value = null
  try {
    revealed.value = await fetchCertificatePassword(props.certificate.id, version)
  } catch {
    localError.value = t('certVersions.passwordFailed')
  }
}

const remove = async (version: number) => {
  if (!props.certificate) return
  if (!confirm(t('certVersions.deleteConfirm', { version }))) return
  await store.remove(props.certificate.id, version)
}
</script>

<style scoped>
.vt-table { margin-top: 8px; }
.vt-version-cell { display: flex; align-items: center; gap: 8px; }
.vt-row-actions { display: flex; gap: 6px; flex-wrap: nowrap; }
.vt-empty { text-align: center; padding: 16px; color: var(--vt-muted); font-style: italic; }
.vt-secret {
  margin-top: 10px;
  padding: 8px 12px;
  border: 1px solid var(--vt-border);
  border-radius: 6px;
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 13px;
}
.vt-secret code { font-family: monospace; word-break: break-all; background: rgba(127,127,127,0.12); padding: 2px 6px; border-radius: 4px; }
.vt-mono { color: var(--vt-muted); }
.vt-error { background: var(--vt-err); color: #fff; padding: 8px 12px; border-radius: 6px; margin-top: 10px; font-size: 13px; }
</style>
