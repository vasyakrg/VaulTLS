<template>
  <div>
    <header class="vt-head">
      <div>
        <h1>{{ $t('ca.title') }}</h1>
        <p class="vt-sub">{{ $t('ca.subtitle') }}</p>
      </div>
      <div class="vt-actions" v-if="authStore.isAdmin">
        <Button
          icon="pi pi-upload"
          severity="secondary"
          outlined
          v-tooltip.top="$t('ca.importCa')"
          :aria-label="$t('ca.importCa')"
          @click="showImportCa = true"
        />
        <Button
          id="CreateCAButton"
          icon="pi pi-plus"
          v-tooltip.top="$t('ca.createCa')"
          :aria-label="$t('ca.createCa')"
          @click="showCreateModal"
        />
      </div>
    </header>

    <div v-if="loading" class="vt-status">{{ $t('ca.loadingCas') }}</div>
    <div v-if="error" class="vt-error">{{ error }}</div>

    <DataTable
      :value="casArray"
      dataKey="id"
      :globalFilterFields="['name.cn', 'name.ou']"
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
        </div>
      </template>

      <Column field="name.cn" :header="$t('common.colName')" sortable>
        <template #body="{ data }">
          <div>{{ data.name.cn }}</div>
          <div v-if="certsByCaId.get(data.id)?.length" class="vt-ca-certs">
            {{ certsByCaId.get(data.id)!.join(', ') }}
          </div>
        </template>
      </Column>
      <Column v-if="hasAnyOU" field="name.ou" :header="$t('common.colGroup')">
        <template #body="{ data }">{{ data.name.ou ?? '' }}</template>
      </Column>
      <Column field="ca_type" :header="$t('common.colType')" sortable>
        <template #body="{ data }">{{ CAType[data.ca_type] }}</template>
      </Column>
      <Column field="created_on" :header="$t('common.colCreatedOn')" sortable>
        <template #body="{ data }">{{ new Date(data.created_on).toLocaleDateString() }}</template>
      </Column>
      <Column field="valid_until" :header="$t('common.colValidUntil')" sortable>
        <template #body="{ data }">
          <span v-if="data.valid_until !== -1">{{ new Date(data.valid_until).toLocaleDateString() }}</span>
        </template>
      </Column>
      <Column :header="$t('ca.colSource')">
        <template #body="{ data }">
          <Tag
            :severity="data.is_imported ? 'secondary' : 'success'"
            :value="data.is_imported ? $t('ca.tagImported') : $t('ca.tagInternal')"
          />
        </template>
      </Column>
      <Column :header="$t('common.actions')">
        <template #body="{ data }">
          <div class="vt-row-actions">
            <Button
              :id="'DownloadButton-' + data.id"
              icon="pi pi-download"
              severity="secondary"
              outlined
              size="small"
              v-tooltip.top="$t('common.download')"
              :aria-label="$t('common.download')"
              @click="downloadCA(data.id)"
            />
            <Button
              v-if="data.has_private_key"
              icon="pi pi-ellipsis-v"
              severity="secondary"
              outlined
              size="small"
              v-tooltip.top="$t('ca.toggle_dropdown')"
              :aria-label="$t('ca.toggle_dropdown')"
              @click="(event) => { crlMenuRefs[data.id]?.toggle(event) }"
            />
            <Menu
              v-if="data.has_private_key"
              :ref="(el) => { crlMenuRefs[data.id] = el as InstanceType<typeof Menu> | null }"
              :model="getCrlMenuItems(data)"
              popup
            />
            <Button
              v-if="authStore.isAdmin"
              :id="'DeleteButton-' + data.id"
              icon="pi pi-trash"
              severity="danger"
              outlined
              size="small"
              v-tooltip.top="$t('common.delete')"
              :aria-label="$t('common.delete')"
              @click="confirmDeletion(data)"
            />
          </div>
        </template>
      </Column>

      <template #empty>
        <div class="vt-empty">{{ $t('ca.noCasFound') }}</div>
      </template>
    </DataTable>

    <!-- ImportCaDialog -->
    <ImportCaDialog v-model:visible="showImportCa" @imported="caStore.fetchCAs()" />

    <!-- Create CA Dialog -->
    <BaseModal
      v-model:visible="isCreateModalVisible"
      :title="$t('ca.createModal.title')"
      :submitLabel="loading ? $t('common.creating') : $t('ca.createModal.create')"
      submitIcon="pi pi-check"
      :submitDisabled="loading || !caReq.ca_name.cn || (!caReq.validity_duration && caReq.ca_type === CAType.TLS)"
      :loading="loading"
      @submit="createCA"
      @cancel="closeCreateModal"
      width="500px"
    >
      <div class="vt-form">
        <div class="vt-field">
          <label>{{ $t('ca.createModal.caName') }}</label>
          <div class="vt-input-group">
            <InputText
              id="caName"
              v-model="caReq.ca_name.cn"
              :placeholder="$t('ca.enterCaCommonName')"
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

        <div v-if="showOUField && caReq.ca_type === CAType.TLS" class="vt-field">
          <label>{{ $t('common.ouGroup') }}</label>
          <InputText
            v-model="caReq.ca_name.ou"
            :placeholder="$t('overview.generateModal.enterOU')"
          />
        </div>

        <div class="vt-field">
          <label>{{ $t('ca.createModal.caType') }}</label>
          <Select
            v-model="caReq.ca_type"
            :options="caTypeOptions"
            optionLabel="label"
            optionValue="value"
            class="vt-select"
          />
        </div>

        <div v-if="caReq.ca_type === CAType.TLS" class="vt-field">
          <label>{{ $t('common.validity') }}</label>
          <div class="vt-input-group">
            <InputNumber
              input-id="validity"
              v-model="caReq.validity_duration"
              :min="1"
              :placeholder="$t('common.enterValidityPeriod')"
              class="vt-input-grow"
            />
            <Select
              id="validity_unit"
              v-model="caReq.validity_unit"
              :options="validityUnitOptions"
              optionLabel="label"
              optionValue="value"
              class="vt-validity-unit"
            />
          </div>
        </div>
      </div>

    </BaseModal>

    <!-- Delete Confirmation Dialog -->
    <BaseModal
      v-model:visible="isDeleteModalVisible"
      :title="$t('ca.deleteModal.title')"
      :submitLabel="$t('common.delete')"
      submitSeverity="danger"
      @submit="deleteCA"
      @cancel="closeDeleteModal"
      width="400px"
    >
      <p>{{ $t('ca.deleteModal.confirm', { name: caToDelete?.name.cn }) }}</p>
    </BaseModal>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import Tooltip from 'primevue/tooltip'
import { useCAStore } from '@/stores/cas'
import { useCertificateStore } from '@/stores/certificates'
import { type CA, type CARequirements, CAType } from '@/types/CA'
import { useAuthStore } from '@/stores/auth'
import { ValidityUnit } from '@/types/ValidityUnit.ts'
import { useI18n } from 'vue-i18n'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Tag from 'primevue/tag'
import Button from 'primevue/button'
import InputText from 'primevue/inputtext'
import InputNumber from 'primevue/inputnumber'
import Select from 'primevue/select'
import { FilterMatchMode } from '@primevue/core/api'
import Menu from 'primevue/menu'
import ImportCaDialog from '@/components/dialogs/ImportCaDialog.vue'
import BaseModal from '@/components/BaseModal.vue'

const { t } = useI18n()

const vTooltip = Tooltip

// stores
const caStore = useCAStore()
const certStore = useCertificateStore()
const authStore = useAuthStore()

// local state
const showImportCa = ref(false)
const filters = ref({ global: { value: null, matchMode: FilterMatchMode.CONTAINS } })

// computed
const cas = computed(() => caStore.cas)
const casArray = computed(() => Array.from(cas.value.values()))
const loading = computed(() => caStore.loading)
const error = computed(() => caStore.error)
const hasAnyOU = computed(() => casArray.value.some((ca) => ca.name.ou))

// map ca_id -> list of certificate names issued by that CA
const certsByCaId = computed(() => {
  const map = new Map<number, string[]>()
  for (const cert of certStore.certificates.values()) {
    if (cert.ca_id == null) continue
    const list = map.get(cert.ca_id) ?? []
    list.push(cert.name.cn)
    map.set(cert.ca_id, list)
  }
  return map
})

// modals state
const isDeleteModalVisible = ref(false)
const isCreateModalVisible = ref(false)
const caToDelete = ref<CA | null>(null)
const showOUField = ref(false)

const caReq = reactive<CARequirements>({
  ca_name: { cn: '', ou: undefined },
  ca_type: CAType.TLS,
  validity_duration: undefined,
  validity_unit: ValidityUnit.Year,
})

// select options
const caTypeOptions = computed(() => [
  { label: 'TLS', value: CAType.TLS },
  { label: 'SSH', value: CAType.SSH },
])

const validityUnitOptions = computed(() => [
  { label: t('common.hours'), value: ValidityUnit.Hour },
  { label: t('common.days'), value: ValidityUnit.Day },
  { label: t('common.months'), value: ValidityUnit.Month },
  { label: t('common.years'), value: ValidityUnit.Year },
])

// lifecycle
onMounted(async () => {
  await Promise.all([caStore.fetchCAs(), certStore.fetchCertificates()])
})

// handlers
const showCreateModal = () => {
  isCreateModalVisible.value = true
}

const closeCreateModal = () => {
  isCreateModalVisible.value = false
  caReq.ca_name = { cn: '', ou: undefined }
  caReq.validity_duration = undefined
  caReq.validity_unit = ValidityUnit.Year
  caReq.ca_type = CAType.TLS
  showOUField.value = false
}

const createCA = async () => {
  await caStore.createCA(caReq)
  closeCreateModal()
}

const confirmDeletion = (ca: CA) => {
  caToDelete.value = ca
  isDeleteModalVisible.value = true
}

const closeDeleteModal = () => {
  caToDelete.value = null
  isDeleteModalVisible.value = false
}

const deleteCA = async () => {
  if (caToDelete.value) {
    await caStore.deleteCA(caToDelete.value.id)
    closeDeleteModal()
  }
}

const downloadCA = async (caId: number) => {
  await caStore.downloadCA(caId)
}

const downloadCRL = async (caId: number, format: string = 'der') => {
  await caStore.downloadCRL(caId, format)
}

const crlMenuRefs = ref<Record<number, InstanceType<typeof Menu> | null>>({})

const getCrlMenuItems = (ca: CA) => {
  if (ca.ca_type === CAType.TLS) {
    return [
      {
        label: `${t('ca.downloadCrl')} (${t('ca.downloadCrlDer')})`,
        icon: 'pi pi-file',
        command: () => downloadCRL(ca.id, 'der'),
      },
      {
        label: `${t('ca.downloadCrl')} (${t('ca.downloadCrlPem')})`,
        icon: 'pi pi-file',
        command: () => downloadCRL(ca.id, 'pem'),
      },
    ]
  } else {
    return [
      {
        label: t('ca.downloadKrl'),
        icon: 'pi pi-file',
        command: () => downloadCRL(ca.id),
      },
    ]
  }
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

.vt-ca-certs {
  font-size: 11px;
  color: var(--vt-muted);
  margin-top: 2px;
  line-height: 1.35;
}

.vt-row-actions {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
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
</style>
