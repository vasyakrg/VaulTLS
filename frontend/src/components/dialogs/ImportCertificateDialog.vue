<template>
  <BaseModal
    :visible="visible"
    @update:visible="$emit('update:visible', $event)"
    :title="$t('importCert.title')"
    :submitLabel="submitting ? $t('importCert.importing') : $t('importCert.import')"
    submitIcon="pi pi-upload"
    :submitDisabled="submitting"
    :loading="submitting"
    @submit="submit"
    @cancel="close"
    width="480px"
  >
    <div class="vt-form">
      <div class="vt-field">
        <label>{{ $t('importCert.mode') }}</label>
        <SelectButton
          v-model="mode"
          :options="modeOptions"
          optionLabel="label"
          optionValue="value"
        />
      </div>

      <div v-if="mode === 'p12'" class="vt-field">
        <label>{{ $t('importCert.p12File') }}</label>
        <div class="drop-zone" :class="{ 'drag-over': dragging.p12 }" @dragover.prevent="dragging.p12 = true" @dragleave="dragging.p12 = false" @drop.prevent="onDropP12">
          <input type="file" accept=".p12,.pfx" @change="onP12Change" />
          <p class="drop-hint">{{ p12File ? p12File.name : 'Перетащите файл или нажмите для выбора' }}</p>
        </div>
      </div>

      <div v-if="mode === 'certkey'" class="vt-field">
        <label>{{ $t('importCert.certFile') }}</label>
        <div class="drop-zone" :class="{ 'drag-over': dragging.cert }" @dragover.prevent="dragging.cert = true" @dragleave="dragging.cert = false" @drop.prevent="onDropCert">
          <input type="file" accept=".pem,.crt,.cer" @change="onCertChange" />
          <p class="drop-hint">{{ certFile ? certFile.name : 'Перетащите файл или нажмите для выбора' }}</p>
        </div>
      </div>

      <div v-if="mode === 'certkey'" class="vt-field">
        <label>{{ $t('importCert.keyFile') }}</label>
        <div class="drop-zone" :class="{ 'drag-over': dragging.key }" @dragover.prevent="dragging.key = true" @dragleave="dragging.key = false" @drop.prevent="onDropKey">
          <input type="file" accept=".pem,.key" @change="onKeyChange" />
          <p class="drop-hint">{{ keyFile ? keyFile.name : 'Перетащите файл или нажмите для выбора' }}</p>
        </div>
      </div>

      <div v-if="mode === 'certkey'" class="vt-field">
        <label>{{ $t('importCert.chainFile') }} <span class="vt-optional">({{ $t('importCert.optional') }})</span></label>
        <div class="drop-zone" :class="{ 'drag-over': dragging.chain }" @dragover.prevent="dragging.chain = true" @dragleave="dragging.chain = false" @drop.prevent="onDropChain">
          <input type="file" accept=".pem,.crt,.cer" @change="onChainChange" />
          <p class="drop-hint">{{ chainFile ? chainFile.name : 'Перетащите файл или нажмите для выбора' }}</p>
        </div>
      </div>

      <div class="vt-field">
        <label>{{ $t('importCert.password') }} <span class="vt-optional">({{ $t('importCert.optional') }})</span></label>
        <Password v-model="password" :feedback="false" toggleMask class="vt-password-full" />
      </div>

      <div class="vt-field">
        <label>{{ $t('importCert.user') }}</label>
        <Select
          v-model="userId"
          :options="userOptions"
          optionLabel="label"
          optionValue="value"
          :placeholder="$t('importCert.selectUser')"
          class="vt-select"
        />
      </div>

      <div class="vt-field">
        <label>{{ $t('importCert.ca') }} <span class="vt-optional">({{ $t('importCert.optional') }})</span></label>
        <Select
          v-model="caId"
          :options="caOptions"
          optionLabel="label"
          optionValue="value"
          :placeholder="$t('importCert.selectCa')"
          class="vt-select"
          showClear
        />
      </div>

      <div class="vt-field">
        <label>{{ $t('importCert.certType') }} <span class="vt-optional">({{ $t('importCert.optional') }})</span></label>
        <Select
          v-model="certType"
          :options="certTypeOptions"
          optionLabel="label"
          optionValue="value"
          :placeholder="$t('importCert.selectCertType')"
          class="vt-select"
          showClear
        />
      </div>

      <div class="vt-field">
        <label>{{ $t('importCert.renewMethod') }} <span class="vt-optional">({{ $t('importCert.optional') }})</span></label>
        <Select
          v-model="renewMethod"
          :options="renewMethodOptions"
          optionLabel="label"
          optionValue="value"
          :placeholder="$t('importCert.selectRenewMethod')"
          class="vt-select"
          showClear
        />
      </div>

      <div v-if="validationErrors.length" class="vt-errors">
        <div v-for="err in validationErrors" :key="err" class="vt-error-item">{{ $t(`import.validation.${err}`) }}</div>
      </div>
    </div>

  </BaseModal>
</template>

<script setup lang="ts">
import { computed, ref, reactive } from 'vue'
import { useI18n } from 'vue-i18n'
import { useToast } from 'primevue/usetoast'
import Select from 'primevue/select'
import Password from 'primevue/password'
import SelectButton from 'primevue/selectbutton'
import { useCertificateStore } from '@/stores/certificates'
import { useUserStore } from '@/stores/users'
import { useCAStore } from '@/stores/cas'
import { validateImportInput } from '@/components/dialogs/importCert'
import BaseModal from '@/components/BaseModal.vue'

const props = defineProps<{ visible: boolean }>()
const emit = defineEmits<{
  (e: 'update:visible', v: boolean): void
  (e: 'imported'): void
}>()

const { t } = useI18n()
const toast = useToast()
const certStore = useCertificateStore()
const userStore = useUserStore()
const caStore = useCAStore()

const mode = ref<'p12' | 'certkey'>('p12')
const p12File = ref<File | null>(null)
const certFile = ref<File | null>(null)
const keyFile = ref<File | null>(null)
const chainFile = ref<File | null>(null)
const dragging = reactive({ p12: false, cert: false, key: false, chain: false })
const password = ref('')
const userId = ref<number | null>(null)
const caId = ref<number | null>(null)
const certType = ref<number | null>(null)
const renewMethod = ref<number | null>(null)
const submitting = ref(false)
const validationErrors = ref<string[]>([])

const modeOptions = computed(() => [
  { label: 'PKCS#12 (.p12)', value: 'p12' },
  { label: 'Cert + Key', value: 'certkey' },
])

const userOptions = computed(() =>
  userStore.users.map((u: { id: number; name: string }) => ({ label: u.name, value: u.id })),
)

const caOptions = computed(() =>
  Array.from(caStore.cas.values()).map((ca) => ({ label: `${ca.name.cn} (ID: ${ca.id})`, value: ca.id })),
)

const certTypeOptions = computed(() => [
  { label: t('overview.generateModal.tlsClient'), value: 0 },
  { label: t('overview.generateModal.tlsServer'), value: 1 },
  { label: t('overview.generateModal.sshClient'), value: 10 },
  { label: t('overview.generateModal.sshServer'), value: 11 },
])

const renewMethodOptions = computed(() => [
  { label: t('overview.generateModal.renewNone'), value: 0 },
  { label: t('overview.generateModal.renewRemind'), value: 1 },
  { label: t('overview.generateModal.renewRenew'), value: 2 },
  { label: t('overview.generateModal.renewAndNotify'), value: 3 },
])

const onP12Change = (e: Event) => {
  p12File.value = (e.target as HTMLInputElement).files?.[0] ?? null
}
const onCertChange = (e: Event) => {
  certFile.value = (e.target as HTMLInputElement).files?.[0] ?? null
}
const onKeyChange = (e: Event) => {
  keyFile.value = (e.target as HTMLInputElement).files?.[0] ?? null
}
const onChainChange = (e: Event) => {
  chainFile.value = (e.target as HTMLInputElement).files?.[0] ?? null
}

const onDropP12 = (e: DragEvent) => {
  dragging.p12 = false
  p12File.value = e.dataTransfer?.files?.[0] ?? null
}
const onDropCert = (e: DragEvent) => {
  dragging.cert = false
  certFile.value = e.dataTransfer?.files?.[0] ?? null
}
const onDropKey = (e: DragEvent) => {
  dragging.key = false
  keyFile.value = e.dataTransfer?.files?.[0] ?? null
}
const onDropChain = (e: DragEvent) => {
  dragging.chain = false
  chainFile.value = e.dataTransfer?.files?.[0] ?? null
}

const resetForm = () => {
  mode.value = 'p12'
  p12File.value = null
  certFile.value = null
  keyFile.value = null
  chainFile.value = null
  password.value = ''
  userId.value = null
  caId.value = null
  certType.value = null
  renewMethod.value = null
  validationErrors.value = []
}

const close = () => {
  resetForm()
  emit('update:visible', false)
}

const submit = async () => {
  validationErrors.value = validateImportInput({
    mode: mode.value,
    userId: userId.value,
    p12: p12File.value,
    cert: certFile.value,
    key: keyFile.value,
  })
  if (validationErrors.value.length) return

  const form = new FormData()
  form.append('user_id', String(userId.value!))
  if (mode.value === 'p12' && p12File.value) form.append('p12', p12File.value)
  if (mode.value === 'certkey') {
    if (certFile.value) form.append('cert', certFile.value)
    if (keyFile.value) form.append('key', keyFile.value)
    if (chainFile.value) form.append('chain', chainFile.value)
  }
  if (password.value) form.append('password', password.value)
  if (caId.value != null) form.append('ca_id', String(caId.value))
  if (certType.value != null) form.append('cert_type', String(certType.value))
  if (renewMethod.value != null) form.append('renew_method', String(renewMethod.value))

  submitting.value = true
  try {
    await certStore.importCertificate(form)
    emit('imported')
    close()
  } catch (err: any) {
    const msg = err?.response?.data?.error ?? t('importCert.errorGeneric')
    toast.add({ severity: 'error', summary: t('importCert.errorTitle'), detail: msg, life: 5000 })
  } finally {
    submitting.value = false
  }
}
</script>

<style scoped>
.vt-form {
  display: flex;
  flex-direction: column;
  gap: 14px;
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

.vt-optional {
  font-weight: 400;
  font-size: 12px;
}

.vt-select {
  width: 100%;
}

.vt-password-full {
  width: 100%;
}

.vt-errors {
  background: var(--vt-err);
  color: #fff;
  border-radius: 6px;
  padding: 8px 12px;
  font-size: 13px;
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.vt-error-item {
  list-style: none;
}

.drop-zone {
  position: relative;
  border: 2px dashed var(--vt-border);
  border-radius: 6px;
  padding: 16px;
  text-align: center;
  cursor: pointer;
  transition: border-color 0.2s, background 0.2s;
}

.drop-zone.drag-over {
  border-color: var(--vt-primary);
  background: color-mix(in srgb, var(--vt-primary) 8%, transparent);
}

.drop-zone input[type="file"] {
  position: absolute;
  inset: 0;
  opacity: 0;
  cursor: pointer;
  width: 100%;
  height: 100%;
}

.drop-hint {
  margin: 0;
  font-size: 13px;
  color: var(--vt-muted);
  pointer-events: none;
}
</style>
