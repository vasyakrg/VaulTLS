<template>
  <div>
    <header class="vt-head">
      <div>
        <h1>{{ $t('le.title') }}</h1>
      </div>
    </header>

    <div v-if="store.loading" class="vt-status">{{ $t('le.loading') }}</div>
    <div v-if="store.error" class="vt-error">{{ store.error }}</div>

    <!-- Providers Section -->
    <div class="vt-section">
      <div class="vt-section-header">
        <h2 class="vt-section-title">{{ $t('le.providers') }}</h2>
        <Button
          icon="pi pi-plus"
          v-tooltip.top="$t('le.addProvider')"
          :aria-label="$t('le.addProvider')"
          @click="openAddProviderModal"
        />
      </div>
      <DataTable :value="store.providers" dataKey="id" class="vt-table">
        <Column field="name" :header="$t('common.colName')" sortable />
        <Column field="directory_url" :header="$t('le.colDirectoryUrl')" />
        <Column field="account_email" :header="$t('le.colEmail')" />
        <Column :header="$t('common.actions')">
          <template #body="{ data }">
            <div class="vt-row-actions">
              <Button
                icon="pi pi-pencil"
                severity="secondary"
                outlined
                size="small"
                v-tooltip.top="$t('le.editProvider')"
                :aria-label="$t('le.editProvider')"
                @click="openEditProviderModal(data)"
              />
              <Button
                icon="pi pi-trash"
                severity="danger"
                outlined
                size="small"
                v-tooltip.top="$t('le.deleteProvider')"
                :aria-label="$t('le.deleteProvider')"
                @click="confirmDeleteProvider(data)"
              />
            </div>
          </template>
        </Column>
        <template #empty>
          <div class="vt-empty">{{ $t('le.noProviders') }}</div>
        </template>
      </DataTable>
    </div>

    <!-- Orders Section -->
    <div class="vt-section vt-section--border-top">
      <div class="vt-section-header">
        <h2 class="vt-section-title">{{ $t('le.orders') }}</h2>
        <Button
          :label="$t('le.newCert')"
          icon="pi pi-plus"
          @click="openNewOrderModal()"
        />
      </div>
      <DataTable :value="store.orders" dataKey="id" class="vt-table">
        <Column field="domain" :header="$t('le.colDomain')" sortable />
        <Column :header="$t('le.wildcard')">
          <template #body="{ data }">{{ data.include_wildcard ? '✓' : '—' }}</template>
        </Column>
        <Column field="status" :header="$t('le.colStatus')" sortable>
          <template #body="{ data }">
            <Tag :severity="orderStatusSeverity(data.status)" :value="data.status" />
          </template>
        </Column>
        <Column :header="$t('le.colCreated')">
          <template #body="{ data }">{{ data.created_on ? new Date(data.created_on).toLocaleDateString() : '—' }}</template>
        </Column>
        <Column :header="$t('common.actions')">
          <template #body="{ data }">
            <div class="vt-row-actions">
              <Button
                v-if="data.status === 'valid'"
                :label="$t('le.renew')"
                icon="pi pi-refresh"
                severity="secondary"
                outlined
                size="small"
                @click="openNewOrderModal(data)"
              />
              <Button
                v-if="data.status === 'pending_dns' || data.status === 'ready' || data.status === 'failed'"
                :icon="data.status === 'failed' ? 'pi pi-replay' : 'pi pi-list'"
                :severity="data.status === 'failed' ? 'warn' : 'secondary'"
                outlined
                size="small"
                v-tooltip.top="data.status === 'failed' ? $t('le.retry') : $t('le.showTxt')"
                :aria-label="data.status === 'failed' ? $t('le.retry') : $t('le.showTxt')"
                @click="openExistingTxtModal(data)"
              />
              <Button
                icon="pi pi-trash"
                severity="danger"
                outlined
                size="small"
                v-tooltip.top="$t('le.deleteOrder')"
                :aria-label="$t('le.deleteOrder')"
                @click="confirmDeleteOrder(data)"
              />
            </div>
          </template>
        </Column>
        <template #empty>
          <div class="vt-empty">{{ $t('le.noOrders') }}</div>
        </template>
      </DataTable>
    </div>

    <!-- Add / Edit Provider Modal -->
    <BaseModal
      v-model:visible="isAddProviderVisible"
      :title="editingProviderId !== null ? $t('le.editProvider') : $t('le.addProvider')"
      :submitLabel="editingProviderId !== null ? $t('common.save') : (store.loading ? $t('common.creating') : $t('le.createProvider'))"
      submitIcon="pi pi-check"
      :submitDisabled="store.loading || !providerForm.name || !providerForm.directory_url || !providerForm.account_email"
      :loading="store.loading"
      @submit="submitAddProvider"
      @cancel="closeAddProviderModal"
      width="500px"
    >
      <div class="vt-form">
        <div class="vt-field">
          <label>{{ $t('common.colName') }}</label>
          <InputText v-model="providerForm.name" :placeholder="$t('le.providerNamePlaceholder')" />
        </div>
        <div class="vt-field">
          <label>{{ $t('le.colDirectoryUrl') }}</label>
          <InputText
            v-model="providerForm.directory_url"
            placeholder="https://acme-v02.api.letsencrypt.org/directory"
          />
        </div>
        <div class="vt-field">
          <label>{{ $t('le.colEmail') }}</label>
          <InputText v-model="providerForm.account_email" placeholder="admin@example.com" />
        </div>
        <div class="vt-field">
          <label>{{ $t('le.eabKid') }}</label>
          <InputText v-model="providerForm.eab_kid" :placeholder="$t('le.eabOptional')" />
        </div>
        <div class="vt-field">
          <label>{{ $t('le.eabHmacKey') }}</label>
          <Password v-model="providerForm.eab_hmac_key" :placeholder="$t('le.eabOptional')" :feedback="false" toggleMask class="vt-password-field" />
        </div>
      </div>
    </BaseModal>

    <!-- New Order Wizard Modal -->
    <BaseModal
      v-model:visible="isNewOrderVisible"
      :title="$t('le.newCert')"
      :submitLabel="store.loading ? $t('common.creating') : $t('le.createOrder')"
      submitIcon="pi pi-check"
      :submitDisabled="store.loading || orderForm.provider_id === undefined || !orderForm.domain"
      :loading="store.loading"
      @submit="submitNewOrder"
      @cancel="closeNewOrderModal"
      width="480px"
    >
      <div class="vt-form">
        <div class="vt-field">
          <label>{{ $t('le.provider') }}</label>
          <Select
            v-model="orderForm.provider_id"
            :options="store.providers"
            optionLabel="name"
            optionValue="id"
            :placeholder="$t('le.selectProvider')"
            class="vt-select"
          />
        </div>
        <div class="vt-field">
          <label>{{ $t('le.colDomain') }}</label>
          <InputText v-model="orderForm.domain" placeholder="example.com" />
        </div>
        <div class="vt-field vt-switch-field">
          <ToggleSwitch input-id="leWildcard" v-model="orderForm.include_wildcard" />
          <div>
            <label for="leWildcard">{{ $t('le.wildcard') }}</label>
          </div>
        </div>
      </div>
    </BaseModal>

    <!-- TXT Records Modal -->
    <BaseModal
      v-model:visible="isTxtVisible"
      :title="$t('le.txtRecords')"
      :submitLabel="store.loading ? $t('common.creating') : $t('le.checkIssue')"
      submitIcon="pi pi-check"
      :submitDisabled="store.loading"
      :loading="store.loading"
      @submit="checkAndIssue"
      @cancel="closeTxtModal"
      width="620px"
    >
      <div class="vt-form">
        <p class="vt-hint">{{ $t('le.dnsHint') }}</p>
        <p class="vt-note"><i class="pi pi-info-circle" /> {{ $t('le.dnsTiming') }}</p>
        <div v-if="store.error" class="vt-error">{{ store.error }}</div>
        <div v-for="rec in currentTxtRecords" :key="rec.name" class="vt-field">
          <label class="vt-monospace vt-small">{{ rec.name }}</label>
          <div class="vt-input-group">
            <InputText :value="rec.value" readonly class="vt-input-grow vt-monospace" />
            <Button
              icon="pi pi-copy"
              severity="secondary"
              outlined
              v-tooltip.top="$t('le.copyValue')"
              :aria-label="$t('le.copyValue')"
              @click="copyToClipboard(rec.value)"
            />
          </div>
        </div>
      </div>
    </BaseModal>

    <!-- Delete Provider Confirmation Modal -->
    <BaseModal
      v-if="providerToDelete"
      v-model:visible="isDeleteProviderVisible"
      :title="$t('le.deleteProviderTitle')"
      :submitLabel="$t('le.deleteProvider')"
      submitSeverity="danger"
      @submit="doDeleteProvider"
      @cancel="closeDeleteProvider"
      width="400px"
    >
      <p>{{ $t('le.deleteProviderConfirm', { name: providerToDelete?.name }) }}</p>
    </BaseModal>

    <!-- Delete Order Confirmation Modal -->
    <BaseModal
      v-if="orderToDelete"
      v-model:visible="isDeleteOrderVisible"
      :title="$t('le.deleteOrderTitle')"
      :submitLabel="$t('le.deleteOrder')"
      submitSeverity="danger"
      @submit="doDeleteOrder"
      @cancel="closeDeleteOrder"
      width="400px"
    >
      <p>{{ $t('le.deleteOrderConfirm', { domain: orderToDelete?.domain }) }}</p>
    </BaseModal>
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import Tooltip from 'primevue/tooltip'
import { useAcmeClientStore } from '@/stores/acmeClient'
import type { AcmeClientProvider, AcmeClientOrder, TxtRecord, CreateProviderRequest } from '@/types/AcmeClient'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Tag from 'primevue/tag'
import Button from 'primevue/button'
import InputText from 'primevue/inputtext'
import Password from 'primevue/password'
import Select from 'primevue/select'
import ToggleSwitch from 'primevue/toggleswitch'
import BaseModal from '@/components/BaseModal.vue'

const vTooltip = Tooltip

const store = useAcmeClientStore()

// ── Add Provider ─────────────────────────────────────────────────────────────

const isAddProviderVisible = ref(false)
const editingProviderId = ref<number | null>(null)
const providerForm = reactive({
  name: '',
  directory_url: '',
  account_email: '',
  eab_kid: '',
  eab_hmac_key: '',
})

const openAddProviderModal = () => {
  editingProviderId.value = null
  // Defensive reset: clears any residual data if a prior edit modal was
  // dismissed through a path that skipped the cancel handler.
  providerForm.name = ''
  providerForm.directory_url = ''
  providerForm.account_email = ''
  providerForm.eab_kid = ''
  providerForm.eab_hmac_key = ''
  isAddProviderVisible.value = true
}

const openEditProviderModal = (provider: AcmeClientProvider) => {
  editingProviderId.value = provider.id
  providerForm.name = provider.name
  providerForm.directory_url = provider.directory_url
  providerForm.account_email = provider.account_email ?? ''
  providerForm.eab_kid = provider.eab_kid ?? ''
  providerForm.eab_hmac_key = '' // write-only; leave blank = unchanged
  isAddProviderVisible.value = true
}

const closeAddProviderModal = () => {
  isAddProviderVisible.value = false
  editingProviderId.value = null
  providerForm.name = ''
  providerForm.directory_url = ''
  providerForm.account_email = ''
  providerForm.eab_kid = ''
  providerForm.eab_hmac_key = ''
}

const submitAddProvider = async () => {
  const req: CreateProviderRequest = {
    name: providerForm.name,
    directory_url: providerForm.directory_url,
    account_email: providerForm.account_email,
  }
  if (providerForm.eab_kid) req.eab_kid = providerForm.eab_kid
  if (providerForm.eab_hmac_key) req.eab_hmac_key = providerForm.eab_hmac_key
  try {
    if (editingProviderId.value !== null) {
      await store.editProvider(editingProviderId.value, req)
    } else {
      await store.addProvider(req)
    }
    closeAddProviderModal()
  } catch {
    // store.error is set; stay open so user can see the error
  }
}

// ── Delete Provider ───────────────────────────────────────────────────────────

const isDeleteProviderVisible = ref(false)
const providerToDelete = ref<AcmeClientProvider | null>(null)

const confirmDeleteProvider = (provider: AcmeClientProvider) => {
  providerToDelete.value = provider
  isDeleteProviderVisible.value = true
}

const closeDeleteProvider = () => {
  isDeleteProviderVisible.value = false
  providerToDelete.value = null
}

const doDeleteProvider = async () => {
  if (!providerToDelete.value) return
  try {
    await store.removeProvider(providerToDelete.value.id)
    closeDeleteProvider()
  } catch {
    // store.error is set
  }
}

// ── New Order Wizard ──────────────────────────────────────────────────────────

const isNewOrderVisible = ref(false)
const orderForm = reactive<{
  provider_id: number | undefined
  domain: string
  include_wildcard: boolean
}>({
  provider_id: undefined,
  domain: '',
  include_wildcard: false,
})

const openNewOrderModal = (renewFrom?: AcmeClientOrder) => {
  if (renewFrom) {
    orderForm.provider_id = renewFrom.provider_id
    orderForm.domain = renewFrom.domain
    orderForm.include_wildcard = renewFrom.include_wildcard
  } else {
    orderForm.provider_id = undefined
    orderForm.domain = ''
    orderForm.include_wildcard = false
  }
  isNewOrderVisible.value = true
}

const closeNewOrderModal = () => {
  isNewOrderVisible.value = false
  orderForm.provider_id = undefined
  orderForm.domain = ''
  orderForm.include_wildcard = false
}

// ── TXT Records ───────────────────────────────────────────────────────────────

const isTxtVisible = ref(false)
const currentOrderId = ref<number | null>(null)
const currentTxtRecords = ref<TxtRecord[]>([])

const openExistingTxtModal = (order: AcmeClientOrder) => {
  store.error = null
  currentOrderId.value = order.id
  currentTxtRecords.value = order.txt_records ?? []
  isTxtVisible.value = true
}

const closeTxtModal = () => {
  isTxtVisible.value = false
  currentOrderId.value = null
  currentTxtRecords.value = []
}

const submitNewOrder = async () => {
  if (orderForm.provider_id === undefined) return
  try {
    const response = await store.newOrder({
      provider_id: orderForm.provider_id,
      domain: orderForm.domain,
      include_wildcard: orderForm.include_wildcard,
    })
    closeNewOrderModal()
    currentOrderId.value = response.order_id
    currentTxtRecords.value = response.txt_records
    isTxtVisible.value = true
  } catch {
    // store.error is set; wizard stays open
  }
}

const checkAndIssue = async () => {
  if (currentOrderId.value === null) return
  try {
    await store.issue(currentOrderId.value)
    closeTxtModal()
  } catch {
    // store.error is set; modal stays open so user can retry or close
  }
}

// ── Delete Order ──────────────────────────────────────────────────────────────

const isDeleteOrderVisible = ref(false)
const orderToDelete = ref<AcmeClientOrder | null>(null)

const confirmDeleteOrder = (order: AcmeClientOrder) => {
  orderToDelete.value = order
  isDeleteOrderVisible.value = true
}

const closeDeleteOrder = () => {
  isDeleteOrderVisible.value = false
  orderToDelete.value = null
}

const doDeleteOrder = async () => {
  if (!orderToDelete.value) return
  try {
    await store.removeOrder(orderToDelete.value.id)
    closeDeleteOrder()
  } catch {
    // store.error is set
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const orderStatusSeverity = (status: string): string => {
  switch (status) {
    case 'valid':
      return 'success'
    case 'failed':
      return 'danger'
    case 'pending_dns':
    case 'ready':
      return 'warn'
    case 'expired':
      return 'secondary'
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

onMounted(async () => {
  await Promise.all([store.fetchProviders(), store.fetchOrders()])
})
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
  white-space: pre-line;
  word-break: break-all;
}

.vt-section {
  margin-bottom: 12px;
}

.vt-section--border-top {
  margin-top: 40px;
  padding-top: 20px;
  border-top: 1px solid var(--vt-border);
}

.vt-section-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 16px;
}

.vt-section-title {
  font-size: 18px;
  font-weight: 600;
}

.vt-table {
  border-radius: 8px;
  overflow: hidden;
  border: 1px solid var(--vt-border);
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

.vt-switch-field {
  flex-direction: row;
  align-items: flex-start;
  gap: 10px;
}

.vt-switch-field > :deep(.p-toggleswitch) {
  flex-shrink: 0;
}

.vt-hint {
  font-size: 13px;
  color: var(--vt-muted);
  margin: 0;
}

.vt-note {
  font-size: 12px;
  line-height: 1.5;
  color: var(--vt-muted);
  margin: 0;
  padding: 8px 10px;
  border-radius: 6px;
  background: color-mix(in srgb, var(--vt-muted) 10%, transparent);
  border-left: 3px solid var(--vt-accent, #a78bfa);
}

.vt-note .pi {
  margin-right: 6px;
  opacity: 0.85;
}

.vt-muted {
  color: var(--vt-muted);
}

.vt-small {
  font-size: 12px;
}

.vt-monospace {
  font-family: monospace;
}

.vt-password-field {
  width: 100%;
}
</style>
