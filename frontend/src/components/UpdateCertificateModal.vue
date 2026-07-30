<template>
  <BaseModal
    :visible="visible"
    :title="$t('certVersions.updateTitle')"
    :submitLabel="$t('certVersions.update')"
    submitIcon="pi pi-upload"
    :submitDisabled="store.loading || !hasFile"
    :loading="store.loading"
    @submit="onSubmit"
    @cancel="onClose"
    @update:visible="(v: boolean) => emit('update:visible', v)"
    width="480px"
  >
    <p class="vt-sub">{{ $t('certVersions.updateHint') }}</p>

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
        <input type="file" accept=".p12,.pfx" @change="onP12" />
      </div>

      <div v-if="mode === 'certkey'" class="vt-field">
        <label>{{ $t('importCert.certFile') }}</label>
        <input type="file" accept=".pem,.crt,.cer" @change="onCert" />
      </div>

      <div v-if="mode === 'certkey'" class="vt-field">
        <label>{{ $t('importCert.keyFile') }}</label>
        <input type="file" accept=".pem,.key" @change="onKey" />
      </div>

      <div v-if="mode === 'certkey'" class="vt-field">
        <label>{{ $t('importCert.chainFile') }} <span class="vt-optional">({{ $t('importCert.optional') }})</span></label>
        <input type="file" accept=".pem,.crt,.cer" @change="onChain" />
      </div>

      <div class="vt-field">
        <label>{{ $t('common.password') }} <span class="vt-optional">({{ $t('importCert.optional') }})</span></label>
        <Password v-model="password" :feedback="false" toggleMask class="vt-password-full" />
      </div>
    </div>

    <div v-if="store.error" class="vt-error">{{ store.error }}</div>
  </BaseModal>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import BaseModal from '@/components/BaseModal.vue'
import Password from 'primevue/password'
import SelectButton from 'primevue/selectbutton'
import { useCertificateVersionStore } from '@/stores/certificateVersions'
import type { Certificate } from '@/types/Certificate'

const props = defineProps<{ visible: boolean; certificate: Certificate | null }>()
const emit = defineEmits<{ 'update:visible': [boolean]; updated: [number] }>()

const store = useCertificateVersionStore()

const mode = ref<'p12' | 'certkey'>('p12')
const modeOptions = [
  { label: 'PKCS#12 (.p12)', value: 'p12' },
  { label: 'Cert + Key', value: 'certkey' },
]

const p12 = ref<File | null>(null)
const cert = ref<File | null>(null)
const key = ref<File | null>(null)
const chain = ref<File | null>(null)
const password = ref('')

const hasFile = computed(() =>
  mode.value === 'p12' ? !!p12.value : !!cert.value && !!key.value,
)

const pick = (target: typeof p12) => (e: Event) => {
  target.value = (e.target as HTMLInputElement).files?.[0] ?? null
}
const onP12 = pick(p12)
const onCert = pick(cert)
const onKey = pick(key)
const onChain = pick(chain)

const resetForm = () => {
  mode.value = 'p12'
  p12.value = null
  cert.value = null
  key.value = null
  chain.value = null
  password.value = ''
  store.error = null
}

watch(
  () => props.visible,
  (open) => {
    if (open) resetForm()
  },
)

const onSubmit = async () => {
  if (!props.certificate || !hasFile.value) return
  const form = new FormData()
  if (mode.value === 'p12' && p12.value) form.append('p12', p12.value)
  if (mode.value === 'certkey') {
    if (cert.value) form.append('cert', cert.value)
    if (key.value) form.append('key', key.value)
    if (chain.value) form.append('chain', chain.value)
  }
  if (password.value) form.append('password', password.value)
  form.append('user_id', String(props.certificate.user_id))

  const ok = await store.update(props.certificate.id, form)
  if (ok) {
    emit('updated', props.certificate.id)
    emit('update:visible', false)
  }
}

const onClose = () => {
  resetForm()
  emit('update:visible', false)
}
</script>

<style scoped>
.vt-form { display: flex; flex-direction: column; gap: 14px; margin-top: 10px; }
.vt-field { display: flex; flex-direction: column; gap: 6px; }
.vt-field label { font-size: 13px; font-weight: 500; color: var(--vt-muted); }
.vt-optional { font-weight: 400; font-size: 12px; }
.vt-password-full { width: 100%; }
.vt-sub { color: var(--vt-muted); font-size: 13px; }
.vt-error { background: var(--vt-err); color: #fff; padding: 8px 12px; border-radius: 6px; margin-top: 10px; font-size: 13px; }
</style>
