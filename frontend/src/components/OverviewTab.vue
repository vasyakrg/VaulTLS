<template>
  <div>
    <header class="vt-head">
      <div>
        <h1>{{ $t('overview.title') }}</h1>
        <p class="vt-sub">{{ $t('certs.subtitle') }}</p>
      </div>
      <div class="vt-actions" v-if="authStore.isAdmin">
        <Button
          :label="$t('certs.import')"
          icon="pi pi-upload"
          severity="secondary"
          outlined
          @click="showImport = true"
        />
        <Button
          id="CreateCertificateButton"
          :label="$t('certs.create')"
          icon="pi pi-plus"
          @click="showGenerateModal"
        />
      </div>
    </header>

    <div v-if="loading" class="vt-status">{{ $t('overview.loadingCerts') }}</div>
    <div v-if="error" class="vt-error">{{ error }}</div>

    <!-- Active Certificates Table -->
    <DataTable
      :value="filteredActiveCertificates"
      dataKey="id"
      :globalFilterFields="['name.cn', 'name.ou', 'ca_id']"
      v-model:filters="filters"
      filterDisplay="menu"
      removableSort
      class="vt-table"
    >
      <template #header>
        <div class="vt-table-header">
          <div class="p-input-icon-left vt-search-wrap">
            <i class="pi pi-search" />
            <InputText
              v-model="filters['global'].value"
              :placeholder="$t('common.search')"
              class="vt-search"
            />
          </div>
          <div class="vt-filter-row">
            <label class="vt-checkbox-label">
              <input
                v-model="hideAcmeCerts"
                type="checkbox"
                class="vt-checkbox"
              />
              {{ $t('overview.hideAcmeCerts') }}
            </label>
          </div>
        </div>
      </template>

      <Column v-if="authStore.isAdmin" field="user_id" :header="$t('overview.colUser')" sortable>
        <template #body="{ data }">{{ userStore.idToName(data.user_id) }}</template>
      </Column>
      <Column field="name.cn" :header="$t('common.colName')" sortable>
        <template #body="{ data }">{{ data.name.cn }}</template>
      </Column>
      <Column v-if="hasAnyOU" field="name.ou" :header="$t('common.colGroup')">
        <template #body="{ data }">{{ data.name.ou ?? '' }}</template>
      </Column>
      <Column field="certificate_type" :header="$t('common.colType')" sortable>
        <template #body="{ data }">{{ CertificateType[data.certificate_type] }}</template>
      </Column>
      <Column field="created_on" :header="$t('common.colCreatedOn')" sortable>
        <template #body="{ data }">{{ new Date(data.created_on).toLocaleDateString() }}</template>
      </Column>
      <Column field="valid_until" :header="$t('common.colValidUntil')" sortable>
        <template #body="{ data }">{{ new Date(data.valid_until).toLocaleDateString() }}</template>
      </Column>
      <Column :header="$t('certs.status')">
        <template #body="{ data }">
          <Tag :severity="statusSeverity(data)" :value="statusLabel(data)" />
        </template>
      </Column>
      <Column field="renew_method" :header="$t('overview.colRenewMethod')" sortable>
        <template #body="{ data }">{{ CertificateRenewMethod[data.renew_method] }}</template>
      </Column>
      <Column field="ca_id" :header="$t('common.colCaId')" sortable />
      <Column :header="$t('common.password')">
        <template #body="{ data }">
          <div class="vt-password-cell">
            <input
              type="text"
              :value="shownCerts.has(data.id) ? (data.password || '') : '•••••••••'"
              readonly
              class="vt-password-input"
              :placeholder="shownCerts.has(data.id) ? $t('overview.generateModal.blank') : undefined"
            />
            <button
              class="vt-icon-btn"
              :title="shownCerts.has(data.id) ? $t('certs.hidePassword') : $t('certs.showPassword')"
              @click="togglePasswordShown(data)"
            >
              <i :class="shownCerts.has(data.id) ? 'pi pi-eye-slash' : 'pi pi-eye'" />
            </button>
            <button
              class="vt-icon-btn"
              :title="$t('certs.copyPassword')"
              @click="copyPasswordtoClipboard(data)"
            >
              <i :class="copiedCerts.has(data.id) ? 'pi pi-check' : 'pi pi-copy'" />
            </button>
          </div>
        </template>
      </Column>
      <Column :header="$t('common.actions')">
        <template #body="{ data }">
          <div class="vt-row-actions">
            <Button
              :id="'DownloadButton-' + data.id"
              :label="$t('common.download')"
              icon="pi pi-download"
              severity="secondary"
              outlined
              size="small"
              @click="downloadCertificate(data.id)"
            />
            <Button
              :label="$t('overview.revoke')"
              icon="pi pi-ban"
              severity="warn"
              outlined
              size="small"
              @click="confirmRevocation(data)"
            />
            <Button
              v-if="authStore.isAdmin"
              :label="$t('common.delete')"
              icon="pi pi-trash"
              severity="danger"
              outlined
              size="small"
              @click="confirmDeletion(data)"
            />
          </div>
        </template>
      </Column>
    </DataTable>

    <!-- Revoked Certificates Section -->
    <div class="vt-revoked-section">
      <div class="vt-revoked-toggle" @click="showRevoked = !showRevoked">
        <span class="vt-revoked-title">{{ $t('overview.revokedSection') }}</span>
        <span class="vt-revoked-chevron">{{ showRevoked ? '−' : '+' }}</span>
      </div>

      <DataTable
        v-if="showRevoked"
        :value="revokedCertificates"
        dataKey="id"
        class="vt-table vt-table-revoked"
        size="small"
      >
        <Column v-if="authStore.isAdmin" field="user_id" :header="$t('overview.colUser')">
          <template #body="{ data }">{{ userStore.idToName(data.user_id) }}</template>
        </Column>
        <Column field="name.cn" :header="$t('common.colName')">
          <template #body="{ data }">{{ data.name.cn }}</template>
        </Column>
        <Column v-if="hasAnyOU" field="name.ou" :header="$t('common.colGroup')">
          <template #body="{ data }">{{ data.name.ou ?? '' }}</template>
        </Column>
        <Column field="certificate_type" :header="$t('common.colType')">
          <template #body="{ data }">{{ CertificateType[data.certificate_type] }}</template>
        </Column>
        <Column field="created_on" :header="$t('overview.colCreated')">
          <template #body="{ data }">{{ new Date(data.created_on).toLocaleDateString() }}</template>
        </Column>
        <Column field="valid_until" :header="$t('overview.colValidity')">
          <template #body="{ data }">{{ new Date(data.valid_until).toLocaleDateString() }}</template>
        </Column>
        <Column field="revoked_at" :header="$t('overview.colRevoked')">
          <template #body="{ data }">
            {{ data.revoked_at ? new Date(data.revoked_at * 1000).toLocaleDateString() : 'Unknown' }}
          </template>
        </Column>
        <Column field="ca_id" :header="$t('common.colCaId')" />
        <Column :header="$t('common.actions')">
          <template #body="{ data }">
            <Button
              :label="$t('common.delete')"
              icon="pi pi-trash"
              severity="danger"
              text
              size="small"
              @click="confirmDeletion(data)"
            />
          </template>
        </Column>
        <template #empty>
          <div class="vt-empty">{{ $t('overview.noRevokedCerts') }}</div>
        </template>
      </DataTable>
    </div>

    <!-- ImportCertificateDialog -->
    <ImportCertificateDialog v-model:visible="showImport" @imported="certificateStore.fetchCertificates()" />

    <!-- Generate Certificate Dialog -->
    <BaseModal
      v-model:visible="isGenerateModalVisible"
      :title="$t('overview.generateModal.title')"
      :submitLabel="loading ? $t('common.creating') : $t('overview.generateModal.create')"
      submitIcon="pi pi-check"
      :submitDisabled="loading || ((!certReq.system_generated_password && certReq.cert_password.length == 0) && passwordRule == PasswordRule.Required)"
      :loading="loading"
      @submit="createCertificate"
      @cancel="closeGenerateModal"
      width="500px"
    >
      <div class="vt-form">
        <div class="vt-field">
          <label>{{ $t('overview.generateModal.commonName') }}</label>
          <div class="vt-input-group">
            <InputText
              v-model="certReq.cert_name.cn"
              :placeholder="$t('overview.generateModal.enterCommonName')"
              class="vt-input-grow"
            />
            <Button
              :label="showOUField ? '−' : '+'"
              severity="secondary"
              outlined
              :title="showOUField ? $t('common.hideOu') : $t('common.addOu')"
              @click="showOUField = !showOUField"
            />
          </div>
        </div>

        <div
          v-if="showOUField && (certReq.cert_type === CertificateType.TLSClient || certReq.cert_type === CertificateType.TLSServer)"
          class="vt-field"
        >
          <label>{{ $t('common.ouGroup') }}</label>
          <InputText
            v-model="certReq.cert_name.ou"
            :placeholder="$t('overview.generateModal.enterOU')"
          />
        </div>

        <div class="vt-field">
          <label>{{ $t('overview.generateModal.certType') }}</label>
          <Select
            v-model="certReq.cert_type"
            :options="certTypeOptions"
            optionLabel="label"
            optionValue="value"
            class="vt-select"
          />
        </div>

        <div
          v-if="certReq.cert_type == CertificateType.TLSServer || certReq.cert_type == CertificateType.SSHClient || certReq.cert_type == CertificateType.SSHServer"
          class="vt-field"
        >
          <label v-if="certReq.cert_type == CertificateType.TLSServer">{{ $t('overview.generateModal.dnsNames') }}</label>
          <label v-else>{{ $t('overview.generateModal.principals') }}</label>
          <div v-for="(_, index) in certReq.usage_limit" :key="index" class="vt-usage-row">
            <InputText
              v-model="certReq.usage_limit[index]"
              :placeholder="$t('overview.generateModal.usagePlaceholder', { n: index + 1 })"
              class="vt-input-grow"
            />
            <Button
              v-if="index === certReq.usage_limit.length - 1"
              label="+"
              severity="secondary"
              outlined
              @click="addUsageField"
            />
            <Button
              v-if="certReq.usage_limit.length > 1"
              label="−"
              severity="danger"
              outlined
              @click="removeUsageField(index)"
            />
          </div>
        </div>

        <div class="vt-field">
          <label>{{ $t('overview.generateModal.user') }}</label>
          <Select
            v-model="certReq.user_id"
            :options="userOptions"
            optionLabel="label"
            optionValue="value"
            :placeholder="$t('overview.generateModal.selectUser')"
            class="vt-select"
          />
        </div>

        <div class="vt-field">
          <label>{{ $t('overview.generateModal.ca') }}</label>
          <Select
            v-model="certReq.ca_id"
            :options="caOptions"
            optionLabel="label"
            optionValue="value"
            :placeholder="$t('overview.generateModal.selectCa')"
            class="vt-select"
          />
        </div>

        <div class="vt-field">
          <label>{{ $t('common.validity') }}</label>
          <div class="vt-input-group">
            <InputNumber
              v-model="certReq.validity_duration"
              :min="0"
              :placeholder="$t('common.enterValidityPeriod')"
              class="vt-input-grow"
            />
            <Select
              v-model="certReq.validity_unit"
              :options="validityUnitOptions"
              optionLabel="label"
              optionValue="value"
              class="vt-validity-unit"
            />
          </div>
        </div>

        <div class="vt-field vt-switch-field">
          <ToggleSwitch
            v-model="certReq.system_generated_password"
            :disabled="passwordRule == PasswordRule.System"
          />
          <label>{{ $t('overview.generateModal.systemPassword') }}</label>
        </div>

        <div v-if="!certReq.system_generated_password" class="vt-field">
          <label>{{ $t('common.password') }}</label>
          <InputText
            v-model="certReq.cert_password"
            :placeholder="$t('overview.generateModal.enterPassword')"
          />
        </div>

        <div class="vt-field">
          <label>{{ $t('overview.generateModal.renewMethod') }}</label>
          <Select
            v-model="certReq.renew_method"
            :options="renewMethodOptions"
            optionLabel="label"
            optionValue="value"
            class="vt-select"
          />
        </div>

        <div v-if="isMailValid" class="vt-field vt-switch-field">
          <ToggleSwitch v-model="certReq.notify_user" />
          <label>{{ $t('overview.generateModal.notifyUser') }}</label>
        </div>
      </div>

    </BaseModal>

    <!-- Revoke Confirmation Dialog -->
    <BaseModal
      v-model:visible="isRevokeModalVisible"
      :title="$t('overview.revokeModal.title')"
      :submitLabel="$t('overview.revokeModal.revoke')"
      submitSeverity="warn"
      @submit="revokeCertificate"
      @cancel="closeRevokeModal"
      width="400px"
    >
      <p>{{ $t('overview.revokeModal.confirm', { name: certToRevoke?.name.cn }) }}</p>
    </BaseModal>

    <!-- Delete Confirmation Dialog -->
    <BaseModal
      v-model:visible="isDeleteModalVisible"
      :title="$t('overview.deleteModal.title')"
      :submitLabel="$t('common.delete')"
      submitSeverity="danger"
      @submit="deleteCertificate"
      @cancel="closeDeleteModal"
      width="400px"
    >
      <p>{{ $t('overview.deleteModal.confirm', { name: certToDelete?.name.cn }) }}</p>
      <p class="vt-disclaimer">{{ $t('overview.deleteModal.disclaimer') }}</p>
    </BaseModal>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { useCertificateStore } from '@/stores/certificates'
import { type Certificate, CertificateRenewMethod, CertificateType } from '@/types/Certificate'
import type { CertificateRequirements } from '@/types/CertificateRequirements'
import { useAuthStore } from '@/stores/auth.ts'
import { useUserStore } from '@/stores/users.ts'
import { useSettingsStore } from '@/stores/settings.ts'
import { PasswordRule } from '@/types/Settings.ts'
import { useCAStore } from '@/stores/cas.ts'
import { CAType } from '@/types/CA.ts'
import { ValidityUnit } from '@/types/ValidityUnit.ts'
import { useI18n } from 'vue-i18n'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Tag from 'primevue/tag'
import Button from 'primevue/button'
import InputText from 'primevue/inputtext'
import InputNumber from 'primevue/inputnumber'
import Select from 'primevue/select'
import ToggleSwitch from 'primevue/toggleswitch'
import { FilterMatchMode } from '@primevue/core/api'
import ImportCertificateDialog from '@/components/dialogs/ImportCertificateDialog.vue'
import BaseModal from '@/components/BaseModal.vue'

const { t } = useI18n()

// stores
const certificateStore = useCertificateStore()
const authStore = useAuthStore()
const userStore = useUserStore()
const settingStore = useSettingsStore()
const caStore = useCAStore()

// local state
const showImport = ref(false)
const shownCerts = ref(new Set<number>())
const copiedCerts = ref(new Set<number>())
const hideAcmeCerts = ref(localStorage.getItem('hideAcmeCerts') === 'true')
watch(hideAcmeCerts, (val) => localStorage.setItem('hideAcmeCerts', String(val)))

const filters = ref({ global: { value: null, matchMode: FilterMatchMode.CONTAINS } })

// computed
const certificates = computed(() => certificateStore.certificates)
const filteredActiveCertificates = computed(() => {
  const all = Array.from(certificates.value.values()).filter((cert) => !cert.revoked_at)
  if (!hideAcmeCerts.value) return all
  return all.filter((cert) => cert.name.ou != 'ACME')
})
const revokedCertificates = computed(() =>
  Array.from(certificates.value.values()).filter((cert) => !!cert.revoked_at),
)
const settings = computed(() => settingStore.settings)
const loading = computed(() => certificateStore.loading)
const error = computed(() => certificateStore.error)
const hasAnyOU = computed(() => Array.from(certificates.value.values()).some((cert) => cert.name.ou))

// modals state
const isDeleteModalVisible = ref(false)
const isGenerateModalVisible = ref(false)
const isRevokeModalVisible = ref(false)
const showRevoked = ref(false)
const showOUField = ref(false)

const certToDelete = ref<Certificate | null>(null)
const certToRevoke = ref<Certificate | null>(null)

const passwordRule = computed(() => settings.value?.common.password_rule ?? PasswordRule.Optional)

const certReq = reactive<CertificateRequirements>({
  cert_name: { cn: '', ou: undefined },
  user_id: 0,
  validity_duration: 1,
  validity_unit: ValidityUnit.Year,
  system_generated_password: passwordRule.value == PasswordRule.System,
  cert_password: '',
  notify_user: false,
  cert_type: CertificateType.TLSClient,
  usage_limit: [''],
  renew_method: CertificateRenewMethod.None,
  ca_id: undefined,
})

const isMailValid = computed(
  () =>
    (settings.value?.mail.smtp_host.length ?? 0) > 0 &&
    (settings.value?.mail.smtp_port ?? 0) > 0,
)

const availableCAs = computed(() => {
  const cas = Array.from(caStore.cas.values())
  const allowedCATypes: Record<number, CAType[]> = {
    [CertificateType.TLSClient]: [CAType.TLS],
    [CertificateType.TLSServer]: [CAType.TLS],
    [CertificateType.SSHClient]: [CAType.SSH],
    [CertificateType.SSHServer]: [CAType.SSH],
  }
  const allowedType = allowedCATypes[certReq.cert_type]
  if (!allowedType) return cas
  return cas.filter((ca) => allowedType.includes(ca.ca_type)).sort((a, b) => b.id - a.id)
})

// select options computed
const certTypeOptions = computed(() => [
  { label: t('overview.generateModal.tlsClient'), value: CertificateType.TLSClient },
  { label: t('overview.generateModal.tlsServer'), value: CertificateType.TLSServer },
  { label: t('overview.generateModal.sshClient'), value: CertificateType.SSHClient },
  { label: t('overview.generateModal.sshServer'), value: CertificateType.SSHServer },
])

const userOptions = computed(() =>
  userStore.users.map((u: { id: number; name: string }) => ({ label: u.name, value: u.id })),
)

const caOptions = computed(() =>
  availableCAs.value.map((ca) => ({ label: `${ca.name.cn} (ID: ${ca.id})`, value: ca.id })),
)

const validityUnitOptions = computed(() => [
  { label: t('common.hours'), value: ValidityUnit.Hour },
  { label: t('common.days'), value: ValidityUnit.Day },
  { label: t('common.months'), value: ValidityUnit.Month },
  { label: t('common.years'), value: ValidityUnit.Year },
])

const renewMethodOptions = computed(() => {
  const base = [
    { label: t('overview.generateModal.renewNone'), value: CertificateRenewMethod.None },
    { label: t('overview.generateModal.renewRemind'), value: CertificateRenewMethod.Notify },
  ]
  if (
    certReq.cert_type == CertificateType.TLSServer ||
    certReq.cert_type == CertificateType.TLSClient
  ) {
    base.push(
      { label: t('overview.generateModal.renewRenew'), value: CertificateRenewMethod.Renew },
      {
        label: t('overview.generateModal.renewAndNotify'),
        value: CertificateRenewMethod.RenewAndNotify,
      },
    )
  }
  return base
})

// status helpers
const statusSeverity = (cert: Certificate): string => {
  if (cert.revoked_at) return 'danger'
  const now = Date.now()
  const until = new Date(cert.valid_until).getTime()
  const warnMs = 30 * 24 * 60 * 60 * 1000
  if (until < now) return 'danger'
  if (until - now < warnMs) return 'warn'
  return 'success'
}

const statusLabel = (cert: Certificate): string => {
  if (cert.revoked_at) return t('certs.statusRevoked')
  const now = Date.now()
  const until = new Date(cert.valid_until).getTime()
  const warnMs = 30 * 24 * 60 * 60 * 1000
  if (until < now) return t('certs.statusExpired')
  if (until - now < warnMs) return t('certs.statusExpiringSoon')
  return t('certs.statusValid')
}

// watchers
watch(passwordRule, (newVal) => {
  certReq.system_generated_password = newVal === PasswordRule.System
}, { immediate: true })

// lifecycle
onMounted(async () => {
  await certificateStore.fetchCertificates()
  if (authStore.isAdmin) {
    await userStore.fetchUsers()
  }
})

// handlers
const showGenerateModal = async () => {
  await userStore.fetchUsers()
  await caStore.fetchCAs()
  isGenerateModalVisible.value = true
}

const closeGenerateModal = () => {
  isGenerateModalVisible.value = false
  certReq.cert_name = { cn: '', ou: undefined }
  certReq.user_id = 0
  certReq.validity_duration = 1
  certReq.validity_unit = ValidityUnit.Year
  certReq.cert_password = ''
  certReq.notify_user = false
  certReq.ca_id = undefined
  showOUField.value = false
}

const createCertificate = async () => {
  await certificateStore.createCertificate(certReq)
  closeGenerateModal()
}

const confirmDeletion = (cert: Certificate) => {
  certToDelete.value = cert
  isDeleteModalVisible.value = true
}

const closeDeleteModal = () => {
  certToDelete.value = null
  isDeleteModalVisible.value = false
}

const downloadCertificate = async (certId: number) => {
  await certificateStore.downloadCertificate(certId)
}

const deleteCertificate = async () => {
  if (certToDelete.value) {
    await certificateStore.deleteCertificate(certToDelete.value.id)
    closeDeleteModal()
  }
}

const confirmRevocation = (cert: Certificate) => {
  certToRevoke.value = cert
  isRevokeModalVisible.value = true
}

const closeRevokeModal = () => {
  certToRevoke.value = null
  isRevokeModalVisible.value = false
}

const revokeCertificate = async () => {
  if (certToRevoke.value) {
    const certId = certToRevoke.value.id
    await certificateStore.revokeCertificate(certId)
    closeRevokeModal()
  }
}

const togglePasswordShown = async (cert: Certificate) => {
  if (!cert.password) {
    await certificateStore.fetchCertificatePassword(cert.id)
  }
  if (shownCerts.value.has(cert.id)) {
    shownCerts.value.delete(cert.id)
  } else {
    shownCerts.value.add(cert.id)
  }
}

const copyPasswordtoClipboard = async (cert: Certificate) => {
  if (!cert.password) {
    await certificateStore.fetchCertificatePassword(cert.id)
  }
  try {
    await navigator.clipboard.writeText(cert.password)
    copiedCerts.value.add(cert.id)
    setTimeout(() => copiedCerts.value.delete(cert.id), 1500)
  } catch (err) {
    console.error('Failed to copy to clipboard: ', err)
  }
}

const addUsageField = () => {
  certReq.usage_limit.push('')
}

const removeUsageField = (index: number) => {
  certReq.usage_limit.splice(index, 1)
}
</script>

<style scoped>
.vt-head {
  display: flex;
  align-items: flex-start;
  margin-bottom: 22px;
}

.vt-head h1 {
  font-size: 22px;
  font-weight: 700;
}

.vt-sub {
  font-size: 13px;
  color: var(--vt-muted);
  margin-top: 3px;
}

.vt-actions {
  margin-left: auto;
  display: flex;
  gap: 10px;
}

.vt-status {
  color: var(--vt-muted);
  font-size: 13px;
  margin-bottom: 12px;
}

.vt-error {
  background: var(--vt-err);
  color: #fff;
  padding: 8px 12px;
  border-radius: 6px;
  margin-bottom: 12px;
  font-size: 13px;
}

.vt-table {
  border-radius: 8px;
  overflow: hidden;
  border: 1px solid var(--vt-border);
}

.vt-table-revoked {
  margin-top: 12px;
  opacity: 0.8;
}

.vt-table-header {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 4px 0;
}

.vt-search-wrap {
  display: flex;
  align-items: center;
  gap: 6px;
  position: relative;
}

.vt-search-wrap i {
  position: absolute;
  left: 10px;
  color: var(--vt-muted);
  z-index: 1;
}

.vt-search {
  padding-left: 32px;
}

.vt-filter-row {
  display: flex;
  align-items: center;
  gap: 8px;
}

.vt-checkbox-label {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 13px;
  color: var(--vt-muted);
  cursor: pointer;
  user-select: none;
}

.vt-checkbox {
  cursor: pointer;
}

.vt-row-actions {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
}

.vt-password-cell {
  display: flex;
  align-items: center;
  gap: 6px;
}

.vt-password-input {
  font-family: monospace;
  width: 100px;
  background: transparent;
  border: 1px solid var(--vt-border);
  border-radius: 4px;
  padding: 2px 6px;
  font-size: 12px;
  color: var(--vt-text);
  overflow: hidden;
}

.vt-icon-btn {
  background: none;
  border: none;
  cursor: pointer;
  padding: 2px 4px;
  color: var(--vt-muted);
  border-radius: 4px;
  transition: color 0.15s;
}

.vt-icon-btn:hover {
  color: var(--vt-text);
}

.vt-revoked-section {
  margin-top: 40px;
  padding-top: 20px;
  border-top: 1px solid var(--vt-border);
}

.vt-revoked-toggle {
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
  user-select: none;
  margin-bottom: 4px;
}

.vt-revoked-title {
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--vt-muted);
}

.vt-revoked-chevron {
  font-size: 14px;
  color: var(--vt-muted);
}

.vt-empty {
  text-align: center;
  padding: 24px;
  color: var(--vt-muted);
  font-size: 13px;
  font-style: italic;
}

.vt-form {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.vt-field {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.vt-field label {
  font-size: 13px;
  font-weight: 500;
  color: var(--vt-muted);
}

.vt-input-group {
  display: flex;
  gap: 8px;
  align-items: center;
}

.vt-input-grow {
  flex: 1;
}

.vt-select {
  width: 100%;
}

.vt-validity-unit {
  width: 130px;
}

.vt-usage-row {
  display: flex;
  gap: 6px;
  align-items: center;
  margin-bottom: 6px;
}

.vt-switch-field {
  flex-direction: row;
  align-items: center;
  gap: 10px;
}

.vt-disclaimer {
  font-size: 12px;
  color: var(--vt-warn);
  margin-top: 8px;
}
</style>
