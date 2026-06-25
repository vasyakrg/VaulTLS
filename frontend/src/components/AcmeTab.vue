<template>
  <div>
    <header class="vt-head">
      <div>
        <h1>{{ $t('acme.title') }}</h1>
        <p class="vt-sub">{{ $t('acme.subtitle') }}</p>
      </div>
      <div class="vt-actions" v-if="authStore.isAdmin">
        <Button
          id="CreateAcmeAccountButton"
          :label="$t('acme.createAccount')"
          icon="pi pi-plus"
          @click="openCreateModal"
        />
      </div>
    </header>

    <div v-if="loading" class="vt-status">{{ $t('acme.loadingAccounts') }}</div>
    <div v-if="error" class="vt-error">{{ error }}</div>

    <!-- Accounts Table -->
    <DataTable
      :value="accountsArray"
      dataKey="id"
      class="vt-table"
    >
      <template #header>
        <div class="vt-table-header">
          <label class="vt-checkbox-label">
            <input
              v-model="hideDeactivated"
              type="checkbox"
              class="vt-checkbox"
            />
            {{ $t('acme.hideDeactivated') }}
          </label>
        </div>
      </template>

      <Column field="id" :header="$t('acme.colId')" sortable />
      <Column field="name" :header="$t('common.colName')" sortable />
      <Column field="allowed_domains" :header="$t('acme.colAllowedDomains')">
        <template #body="{ data }">
          <span :title="data.allowed_domains">{{ truncateDomains(data.allowed_domains) }}</span>
        </template>
      </Column>
      <Column field="status" :header="$t('acme.colStatus')" sortable>
        <template #body="{ data }">
          <Tag
            :severity="accountStatusSeverity(data.status)"
            :value="$te(`acme.${data.status}`) ? $t(`acme.${data.status}`) : data.status"
          />
        </template>
      </Column>
      <Column :header="$t('acme.colValidation')">
        <template #body="{ data }">
          <Tag
            v-if="data.auto_validate"
            severity="warn"
            :value="$t('acme.autoApproved')"
            :title="$t('acme.autoValidateTitle')"
          />
          <Tag
            v-else
            severity="success"
            value="HTTP-01 / DNS-01"
            :title="$t('acme.http01ValidateTitle')"
          />
        </template>
      </Column>
      <Column field="ca_id" :header="$t('common.colCaId')" sortable />
      <Column :header="$t('users.title')">
        <template #body="{ data }">{{ userStore.idToName(data.user_id) }}</template>
      </Column>
      <Column field="created_on" :header="$t('acme.colCreated')" sortable>
        <template #body="{ data }">{{ new Date(data.created_on).toLocaleDateString() }}</template>
      </Column>
      <Column :header="$t('common.actions')">
        <template #body="{ data }">
          <div class="vt-row-actions">
            <Button
              :id="'EditButton-' + data.id"
              v-if="authStore.isAdmin"
              :label="$t('acme.edit')"
              icon="pi pi-pencil"
              severity="secondary"
              outlined
              size="small"
              @click="openEditModal(data)"
            />
            <Button
              :id="'DeleteButton-' + data.id"
              v-if="authStore.isAdmin && data.status !== 'deactivated'"
              :label="$t('acme.deactivate')"
              icon="pi pi-ban"
              severity="danger"
              outlined
              size="small"
              @click="confirmDeletion(data)"
            />
          </div>
        </template>
      </Column>

      <template #empty>
        <div class="vt-empty">{{ $t('acme.noAccounts') }}</div>
      </template>
    </DataTable>

    <!-- Orders Section -->
    <div class="vt-orders-section">
      <h2 class="vt-section-title">{{ $t('acme.ordersTitle') }}</h2>
      <DataTable
        :value="ordersArray"
        dataKey="id"
        class="vt-table"
      >
        <Column field="id" :header="$t('acme.colId')" sortable />
        <Column field="account_name" :header="$t('acme.colAccount')" sortable />
        <Column field="status" :header="$t('acme.colStatus')" sortable>
          <template #body="{ data }">
            <Tag
              :severity="orderStatusSeverity(data.status)"
              :value="$t(`acme.${data.status}`)"
            />
          </template>
        </Column>
        <Column :header="$t('acme.colDomains')">
          <template #body="{ data }">{{ data.identifiers.map((i: { value: string }) => i.value).join(', ') }}</template>
        </Column>
        <Column field="expires" :header="$t('acme.colExpires')" sortable>
          <template #body="{ data }">{{ new Date(data.expires).toLocaleDateString() }}</template>
        </Column>
        <Column :header="$t('acme.colCertId')">
          <template #body="{ data }">{{ data.certificate_id !== null ? data.certificate_id : '—' }}</template>
        </Column>
        <Column :header="$t('acme.colClientIp')">
          <template #body="{ data }">{{ data.client_ip ?? '—' }}</template>
        </Column>
        <Column :header="$t('acme.colError')">
          <template #body="{ data }">
            <span v-if="data.error" :title="data.error" class="vt-error-cell">
              {{ data.error.length > 40 ? data.error.slice(0, 40) + '…' : data.error }}
            </span>
            <span v-else class="vt-muted">—</span>
          </template>
        </Column>

        <template #empty>
          <div class="vt-empty">{{ $t('acme.noOrders') }}</div>
        </template>
      </DataTable>
    </div>

    <!-- Create Dialog -->
    <Dialog
      v-model:visible="isCreateModalVisible"
      :header="$t('acme.createModal.title')"
      modal
      :closable="true"
      :draggable="false"
      :style="{ width: '500px' }"
      @hide="closeCreateModal"
    >
      <div class="vt-form">
        <div class="vt-field">
          <label>{{ $t('common.colName') }}</label>
          <InputText
            id="acmeName"
            v-model="createForm.name"
            :placeholder="$t('acme.createModal.namePlaceholder')"
          />
        </div>

        <div class="vt-field">
          <label>{{ $t('acme.createModal.allowedDomains') }}</label>
          <div class="vt-input-group">
            <InputText
              id="acmeDomainInput"
              v-model="domainInput"
              :placeholder="$t('acme.createModal.domainPlaceholder')"
              class="vt-input-grow"
              @keydown.enter.prevent="addDomain"
            />
            <Button
              :label="$t('acme.createModal.addDomain')"
              severity="secondary"
              outlined
              @click="addDomain"
            />
          </div>
          <div class="vt-tag-list">
            <Tag
              v-for="(domain, index) in createForm.allowed_domains"
              :key="index"
              :value="domain"
              severity="secondary"
              class="vt-domain-tag"
            >
              <template #default>
                {{ domain }}
                <button type="button" class="vt-tag-remove" @click="removeDomain(index)">×</button>
              </template>
            </Tag>
          </div>
          <div v-if="createForm.allowed_domains.length === 0" class="vt-muted vt-small">
            {{ $t('acme.createModal.noDomainsAdded') }}
          </div>
        </div>

        <div class="vt-field">
          <label>{{ $t('overview.generateModal.ca') }}</label>
          <Select
            id="acmeCA"
            v-model="createForm.ca_id"
            :options="caOptions"
            optionLabel="label"
            optionValue="value"
            :placeholder="$t('acme.createModal.selectCa')"
            class="vt-select"
          />
        </div>

        <div class="vt-field vt-switch-field">
          <ToggleSwitch id="acmeAutoValidate" v-model="createForm.auto_validate" />
          <div>
            <label for="acmeAutoValidate">{{ $t('acme.createModal.autoValidate') }}</label>
            <div class="vt-warn-text vt-small">{{ $t('acme.createModal.autoValidateHelp') }}</div>
          </div>
        </div>
      </div>

      <template #footer>
        <Button :label="$t('common.cancel')" severity="secondary" outlined @click="closeCreateModal" />
        <Button
          :label="loading ? $t('common.creating') : $t('acme.createModal.create')"
          icon="pi pi-check"
          :disabled="loading || !createForm.name || !createForm.ca_id"
          @click="createAccount"
        />
      </template>
    </Dialog>

    <!-- Credentials Dialog -->
    <Dialog
      v-if="createdCredentials"
      v-model:visible="isCredentialsModalVisible"
      :header="$t('acme.credentialsModal.title')"
      modal
      :closable="true"
      :draggable="false"
      :style="{ width: '600px' }"
      @hide="closeCredentialsModal"
    >
      <div class="vt-form">
        <div class="vt-warn-banner">{{ $t('acme.credentialsModal.hmacWarning') }}</div>

        <div class="vt-field">
          <label>{{ $t('acme.credentialsModal.eabKeyId') }}</label>
          <div class="vt-input-group">
            <InputText
              :value="createdCredentials.eab_kid"
              readonly
              class="vt-input-grow vt-monospace"
            />
            <Button
              :label="$t('acme.credentialsModal.copy')"
              icon="pi pi-copy"
              severity="secondary"
              outlined
              @click="copyToClipboard(createdCredentials!.eab_kid)"
            />
          </div>
        </div>

        <div class="vt-field">
          <label>{{ $t('acme.credentialsModal.eabHmacKey') }}</label>
          <div class="vt-input-group">
            <InputText
              :value="createdCredentials.eab_hmac_key"
              readonly
              class="vt-input-grow vt-monospace"
            />
            <Button
              :label="$t('acme.credentialsModal.copy')"
              icon="pi pi-copy"
              severity="secondary"
              outlined
              @click="copyToClipboard(createdCredentials!.eab_hmac_key)"
            />
          </div>
        </div>

        <div class="vt-field">
          <label class="vt-section-label">{{ $t('acme.credentialsModal.exampleUsage') }}</label>
          <div class="vt-small vt-muted vt-code-label">certbot</div>
          <pre class="vt-code">certbot certonly \
  --server {{ acmeDirectoryUrl }} \
  --eab-kid {{ createdCredentials.eab_kid }} \
  --eab-hmac-key {{ createdCredentials.eab_hmac_key }} \
  -d your.domain.com</pre>
          <div class="vt-small vt-muted vt-code-label">acme.sh</div>
          <pre class="vt-code">acme.sh --register-account \
  --server {{ acmeDirectoryUrl }} \
  --eab-kid {{ createdCredentials.eab_kid }} \
  --eab-hmac-key {{ createdCredentials.eab_hmac_key }}</pre>
        </div>

        <div class="vt-field">
          <label class="vt-section-label vt-muted vt-small">{{ $t('acme.credentialsModal.dns01Examples') }}</label>
          <div class="vt-small vt-muted vt-code-label">certbot (DNS-01)</div>
          <pre class="vt-code">certbot certonly \
  --server {{ acmeDirectoryUrl }} \
  --eab-kid {{ createdCredentials.eab_kid }} \
  --eab-hmac-key {{ createdCredentials.eab_hmac_key }} \
  --preferred-challenges dns \
  -d your.domain.com</pre>
          <div class="vt-small vt-muted vt-code-label">acme.sh (DNS-01)</div>
          <pre class="vt-code">acme.sh --issue \
  --server {{ acmeDirectoryUrl }} \
  --dns dns_provider \
  -d your.domain.com</pre>
        </div>
      </div>

      <template #footer>
        <Button :label="$t('acme.credentialsModal.close')" @click="closeCredentialsModal" />
      </template>
    </Dialog>

    <!-- Edit Dialog -->
    <Dialog
      v-if="accountToEdit"
      v-model:visible="isEditModalVisible"
      :header="$t('acme.editModal.title')"
      modal
      :closable="true"
      :draggable="false"
      :style="{ width: '500px' }"
      @hide="closeEditModal"
    >
      <div class="vt-form">
        <div class="vt-field">
          <label>{{ $t('common.colName') }}</label>
          <InputText
            id="editAcmeName"
            v-model="editForm.name"
            :placeholder="$t('acme.editModal.namePlaceholder')"
          />
        </div>

        <div class="vt-field">
          <label>{{ $t('overview.generateModal.ca') }}</label>
          <Select
            id="editAcmeCA"
            v-model="editForm.ca_id"
            :options="caOptions"
            optionLabel="label"
            optionValue="value"
            :placeholder="$t('acme.editModal.selectCa')"
            class="vt-select"
          />
        </div>

        <div class="vt-field">
          <label>{{ $t('acme.editModal.allowedDomains') }}</label>
          <div class="vt-input-group">
            <InputText
              id="editDomainInput"
              v-model="editDomainInput"
              :placeholder="$t('acme.editModal.domainPlaceholder')"
              class="vt-input-grow"
              @keydown.enter.prevent="addEditDomain"
            />
            <Button
              :label="$t('acme.editModal.addDomain')"
              severity="secondary"
              outlined
              @click="addEditDomain"
            />
          </div>
          <div class="vt-tag-list">
            <Tag
              v-for="(domain, index) in editForm.allowed_domains"
              :key="index"
              severity="secondary"
              class="vt-domain-tag"
            >
              <template #default>
                {{ domain }}
                <button type="button" class="vt-tag-remove" @click="removeEditDomain(index)">×</button>
              </template>
            </Tag>
          </div>
          <div v-if="editForm.allowed_domains.length === 0" class="vt-muted vt-small">
            {{ $t('acme.editModal.noDomainsAdded') }}
          </div>
        </div>

        <div class="vt-field vt-switch-field">
          <ToggleSwitch id="editAcmeAutoValidate" v-model="editForm.auto_validate" />
          <div>
            <label for="editAcmeAutoValidate">{{ $t('acme.editModal.autoValidate') }}</label>
            <div class="vt-warn-text vt-small">{{ $t('acme.editModal.autoValidateHelp') }}</div>
          </div>
        </div>
      </div>

      <template #footer>
        <Button :label="$t('common.cancel')" severity="secondary" outlined @click="closeEditModal" />
        <Button
          :label="loading ? $t('acme.editModal.saving') : $t('common.save')"
          icon="pi pi-check"
          :disabled="loading || !editForm.name"
          @click="saveEdit"
        />
      </template>
    </Dialog>

    <!-- Deactivate Confirmation Dialog -->
    <Dialog
      v-model:visible="isDeleteModalVisible"
      :header="$t('acme.deactivateModal.title')"
      modal
      :draggable="false"
      :style="{ width: '400px' }"
    >
      <p>{{ $t('acme.deactivateModal.confirm', { name: accountToDelete?.name }) }}</p>
      <template #footer>
        <Button :label="$t('common.cancel')" severity="secondary" outlined @click="closeDeleteModal" />
        <Button
          id="ConfirmDeleteButton"
          :label="$t('acme.deactivateModal.deactivate')"
          severity="danger"
          @click="deleteAccount"
        />
      </template>
    </Dialog>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useAcmeStore } from '@/stores/acme'
import { useCAStore } from '@/stores/cas'
import { useAuthStore } from '@/stores/auth'
import { useUserStore } from '@/stores/users'
import type { AcmeAccount, CreateAcmeAccountResponse } from '@/types/Acme'
import { CAType } from '@/types/CA'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Tag from 'primevue/tag'
import Button from 'primevue/button'
import InputText from 'primevue/inputtext'
import Select from 'primevue/select'
import Dialog from 'primevue/dialog'
import ToggleSwitch from 'primevue/toggleswitch'

// stores
const acmeStore = useAcmeStore()
const caStore = useCAStore()
const authStore = useAuthStore()
const userStore = useUserStore()

// local state
const loading = computed(() => acmeStore.loading)
const error = computed(() => acmeStore.error)

const availableCAs = computed(() =>
  Array.from(caStore.cas.values())
    .filter((ca) => ca.ca_type === CAType.TLS)
    .sort((a, b) => b.id - a.id),
)

const caOptions = computed(() =>
  availableCAs.value.map((ca) => ({ label: `${ca.name.cn} (ID: ${ca.id})`, value: ca.id })),
)

const hideDeactivated = ref(true)
const accountsArray = computed(() => {
  const all = Array.from(acmeStore.accounts.values())
  return hideDeactivated.value ? all.filter((a) => a.status !== 'deactivated') : all
})

const ordersArray = computed(() => Array.from(acmeStore.orders.values()))

const acmeDirectoryUrl = window.location.origin + '/api/acme/directory'

// create modal
const isCreateModalVisible = ref(false)
const domainInput = ref('')
const createForm = reactive<{
  name: string
  allowed_domains: string[]
  ca_id: number | undefined
  auto_validate: boolean
}>({
  name: '',
  allowed_domains: [],
  ca_id: undefined,
  auto_validate: false,
})

// credentials modal
const isCredentialsModalVisible = ref(false)
const createdCredentials = ref<CreateAcmeAccountResponse | null>(null)

// edit modal
const isEditModalVisible = ref(false)
const accountToEdit = ref<AcmeAccount | null>(null)
const editDomainInput = ref('')
const editForm = reactive<{
  name: string
  allowed_domains: string[]
  ca_id: number | undefined
  auto_validate: boolean
}>({
  name: '',
  allowed_domains: [],
  ca_id: undefined,
  auto_validate: false,
})

// delete modal
const isDeleteModalVisible = ref(false)
const accountToDelete = ref<AcmeAccount | null>(null)

onMounted(async () => {
  await Promise.all([
    acmeStore.fetchAccounts(),
    acmeStore.fetchOrders(),
    caStore.fetchCAs(),
    userStore.fetchUsers(),
  ])
})

// helpers
const truncateDomains = (domains: string): string => {
  if (domains.length <= 40) return domains
  return domains.slice(0, 40) + '...'
}

const accountStatusSeverity = (status: string): string => {
  switch (status) {
    case 'valid':
      return 'success'
    case 'pending':
      return 'secondary'
    case 'deactivated':
      return 'danger'
    default:
      return 'secondary'
  }
}

const orderStatusSeverity = (status: string): string => {
  switch (status) {
    case 'valid':
      return 'success'
    case 'ready':
      return 'info'
    case 'pending':
      return 'secondary'
    case 'invalid':
      return 'danger'
    default:
      return 'secondary'
  }
}

const copyToClipboard = async (text: string) => {
  try {
    await navigator.clipboard.writeText(text)
  } catch (err) {
    console.error('Failed to copy to clipboard', err)
  }
}

// create modal actions
const openCreateModal = () => {
  isCreateModalVisible.value = true
}

const closeCreateModal = () => {
  isCreateModalVisible.value = false
  createForm.name = ''
  createForm.allowed_domains = []
  createForm.ca_id = undefined
  createForm.auto_validate = false
  domainInput.value = ''
}

const addDomain = () => {
  const d = domainInput.value.trim()
  if (d && !createForm.allowed_domains.includes(d)) {
    createForm.allowed_domains.push(d)
  }
  domainInput.value = ''
}

const removeDomain = (index: number) => {
  createForm.allowed_domains.splice(index, 1)
}

const createAccount = async () => {
  const result = await acmeStore.createAccount({
    name: createForm.name,
    allowed_domains: createForm.allowed_domains,
    ca_id: createForm.ca_id!,
    auto_validate: createForm.auto_validate,
  })
  closeCreateModal()
  if (result) {
    createdCredentials.value = result
    isCredentialsModalVisible.value = true
  }
}

// credentials modal actions
const closeCredentialsModal = () => {
  isCredentialsModalVisible.value = false
  createdCredentials.value = null
}

// edit modal actions
const openEditModal = (account: AcmeAccount) => {
  accountToEdit.value = account
  editForm.name = account.name
  editForm.allowed_domains = account.allowed_domains
    ? account.allowed_domains
        .split(',')
        .map((d) => d.trim())
        .filter((d) => d.length > 0)
    : []
  editForm.ca_id = account.ca_id
  editForm.auto_validate = account.auto_validate
  editDomainInput.value = ''
  isEditModalVisible.value = true
}

const closeEditModal = () => {
  isEditModalVisible.value = false
  accountToEdit.value = null
  editForm.ca_id = undefined
  editDomainInput.value = ''
}

const addEditDomain = () => {
  const d = editDomainInput.value.trim()
  if (d && !editForm.allowed_domains.includes(d)) {
    editForm.allowed_domains.push(d)
  }
  editDomainInput.value = ''
}

const removeEditDomain = (index: number) => {
  editForm.allowed_domains.splice(index, 1)
}

const saveEdit = async () => {
  if (accountToEdit.value) {
    await acmeStore.updateAccount(accountToEdit.value.id, {
      name: editForm.name,
      allowed_domains: editForm.allowed_domains,
      ca_id: editForm.ca_id,
      auto_validate: editForm.auto_validate,
    })
    closeEditModal()
  }
}

// delete modal actions
const confirmDeletion = (account: AcmeAccount) => {
  accountToDelete.value = account
  isDeleteModalVisible.value = true
}

const closeDeleteModal = () => {
  accountToDelete.value = null
  isDeleteModalVisible.value = false
}

const deleteAccount = async () => {
  if (accountToDelete.value) {
    await acmeStore.deleteAccount(accountToDelete.value.id)
    closeDeleteModal()
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

.vt-empty {
  text-align: center;
  padding: 24px;
  color: var(--vt-muted);
  font-size: 13px;
  font-style: italic;
}

.vt-orders-section {
  margin-top: 40px;
  padding-top: 20px;
  border-top: 1px solid var(--vt-border);
}

.vt-section-title {
  font-size: 18px;
  font-weight: 600;
  margin-bottom: 16px;
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

.vt-switch-field {
  flex-direction: row;
  align-items: flex-start;
  gap: 10px;
}

.vt-tag-list {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-top: 4px;
}

.vt-domain-tag {
  display: inline-flex;
  align-items: center;
  gap: 4px;
}

.vt-tag-remove {
  background: none;
  border: none;
  cursor: pointer;
  padding: 0 2px;
  font-size: 14px;
  line-height: 1;
  color: inherit;
  opacity: 0.7;
}

.vt-tag-remove:hover {
  opacity: 1;
}

.vt-muted {
  color: var(--vt-muted);
}

.vt-small {
  font-size: 12px;
}

.vt-warn-text {
  color: var(--vt-warn);
}

.vt-warn-banner {
  background: color-mix(in srgb, var(--vt-warn, #f59e0b) 15%, transparent);
  border: 1px solid color-mix(in srgb, var(--vt-warn, #f59e0b) 40%, transparent);
  border-radius: 6px;
  padding: 10px 14px;
  font-size: 13px;
  font-weight: 500;
}

.vt-code {
  background: var(--vt-code-bg, color-mix(in srgb, currentColor 8%, transparent));
  border: 1px solid var(--vt-border);
  border-radius: 6px;
  padding: 10px 12px;
  font-size: 12px;
  white-space: pre-wrap;
  word-break: break-all;
  font-family: monospace;
  margin: 0;
}

.vt-code-label {
  margin-top: 8px;
  margin-bottom: 2px;
}

.vt-section-label {
  font-weight: 600;
}

.vt-monospace {
  font-family: monospace;
}

.vt-error-cell {
  color: var(--vt-err, #dc2626);
  cursor: help;
}
</style>
