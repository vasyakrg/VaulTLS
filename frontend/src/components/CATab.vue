<template>
  <div>
    <header class="vt-head">
      <div>
        <h1>{{ $t('ca.title') }}</h1>
        <p class="vt-sub">{{ $t('ca.subtitle') }}</p>
      </div>
      <div class="vt-actions" v-if="authStore.isAdmin">
        <Button
          :label="$t('ca.importCa')"
          icon="pi pi-upload"
          severity="secondary"
          outlined
          @click="showImportCa = true"
        />
        <Button
          id="CreateCAButton"
          :label="$t('ca.createCa')"
          icon="pi pi-plus"
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
        <template #body="{ data }">{{ data.name.cn }}</template>
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
              :label="$t('common.download')"
              icon="pi pi-download"
              severity="secondary"
              outlined
              size="small"
              @click="downloadCA(data.id)"
            />
            <template v-if="data.ca_type === CAType.TLS">
              <Button
                :id="'CRLButton-' + data.id"
                :label="$t('ca.downloadCrl') + ' (DER)'"
                icon="pi pi-file"
                severity="secondary"
                outlined
                size="small"
                @click="downloadCRL(data.id, 'der')"
              />
              <Button
                :label="$t('ca.downloadCrl') + ' (PEM)'"
                icon="pi pi-file"
                severity="secondary"
                outlined
                size="small"
                @click="downloadCRL(data.id, 'pem')"
              />
            </template>
            <Button
              v-if="data.ca_type === CAType.SSH"
              :id="'KRLButton-' + data.id"
              :label="$t('ca.downloadKrl')"
              icon="pi pi-file"
              severity="secondary"
              outlined
              size="small"
              @click="downloadCRL(data.id)"
            />
            <Button
              v-if="authStore.isAdmin"
              :id="'DeleteButton-' + data.id"
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

      <template #empty>
        <div class="vt-empty">No CAs found.</div>
      </template>
    </DataTable>

    <!-- ImportCaDialog -->
    <ImportCaDialog v-model:visible="showImportCa" @imported="caStore.fetchCAs()" />

    <!-- Create CA Dialog -->
    <Dialog
      v-model:visible="isCreateModalVisible"
      :header="$t('ca.createModal.title')"
      modal
      :closable="true"
      :draggable="false"
      :style="{ width: '500px' }"
      @hide="closeCreateModal"
    >
      <div class="vt-form">
        <div class="vt-field">
          <label>{{ $t('ca.createModal.caName') }}</label>
          <div class="vt-input-group">
            <InputText
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
            placeholder="Enter organizational unit (optional)"
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
              v-model="caReq.validity_duration"
              :min="1"
              :placeholder="$t('common.enterValidityPeriod')"
              class="vt-input-grow"
            />
            <Select
              v-model="caReq.validity_unit"
              :options="validityUnitOptions"
              optionLabel="label"
              optionValue="value"
              class="vt-validity-unit"
            />
          </div>
        </div>
      </div>

      <template #footer>
        <Button :label="$t('common.cancel')" severity="secondary" outlined @click="closeCreateModal" />
        <Button
          :label="loading ? $t('common.creating') : $t('ca.createModal.create')"
          icon="pi pi-check"
          :disabled="loading || !caReq.ca_name.cn || (!caReq.validity_duration && caReq.ca_type === CAType.TLS)"
          @click="createCA"
        />
      </template>
    </Dialog>

    <!-- Delete Confirmation Dialog -->
    <Dialog
      v-model:visible="isDeleteModalVisible"
      :header="$t('ca.deleteModal.title')"
      modal
      :draggable="false"
      :style="{ width: '400px' }"
    >
      <p>{{ $t('ca.deleteModal.confirm', { name: caToDelete?.name.cn }) }}</p>
      <template #footer>
        <Button :label="$t('common.cancel')" severity="secondary" outlined @click="closeDeleteModal" />
        <Button :label="$t('common.delete')" severity="danger" @click="deleteCA" />
      </template>
    </Dialog>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useCAStore } from '@/stores/cas'
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
import Dialog from 'primevue/dialog'
import { FilterMatchMode } from '@primevue/core/api'
import ImportCaDialog from '@/components/dialogs/ImportCaDialog.vue'

const { t } = useI18n()

// stores
const caStore = useCAStore()
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
  await caStore.fetchCAs()
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
