<template>
  <Dialog
    :visible="visible"
    @update:visible="$emit('update:visible', $event)"
    :header="$t('importCa.title')"
    modal
    :draggable="false"
    :style="{ width: '480px' }"
  >
    <div class="vt-form">
      <div class="vt-field">
        <label>{{ $t('importCa.caCertFile') }}</label>
        <input type="file" accept=".pem,.crt,.cer" @change="onCaCertChange" />
      </div>

      <div class="vt-field">
        <label>{{ $t('importCa.caKeyFile') }} <span class="vt-optional">({{ $t('importCa.optional') }})</span></label>
        <input type="file" accept=".pem,.key" @change="onCaKeyChange" />
      </div>

      <div class="vt-field">
        <label>{{ $t('importCa.name') }} <span class="vt-optional">({{ $t('importCa.optional') }})</span></label>
        <InputText v-model="name" :placeholder="$t('importCa.namePlaceholder')" class="vt-input-full" />
      </div>

      <div v-if="validationErrors.length" class="vt-errors">
        <div v-for="err in validationErrors" :key="err" class="vt-error-item">{{ err }}</div>
      </div>
    </div>

    <template #footer>
      <Button :label="$t('common.cancel')" severity="secondary" outlined @click="close" />
      <Button
        :label="submitting ? $t('importCa.importing') : $t('importCa.import')"
        icon="pi pi-upload"
        :disabled="submitting"
        @click="submit"
      />
    </template>
  </Dialog>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useToast } from 'primevue/usetoast'
import Dialog from 'primevue/dialog'
import Button from 'primevue/button'
import InputText from 'primevue/inputtext'
import { useCAStore } from '@/stores/cas'

const props = defineProps<{ visible: boolean }>()
const emit = defineEmits<{
  (e: 'update:visible', v: boolean): void
  (e: 'imported'): void
}>()

const { t } = useI18n()
const toast = useToast()
const caStore = useCAStore()

const caCertFile = ref<File | null>(null)
const caKeyFile = ref<File | null>(null)
const name = ref('')
const submitting = ref(false)
const validationErrors = ref<string[]>([])

const onCaCertChange = (e: Event) => {
  caCertFile.value = (e.target as HTMLInputElement).files?.[0] ?? null
}
const onCaKeyChange = (e: Event) => {
  caKeyFile.value = (e.target as HTMLInputElement).files?.[0] ?? null
}

const resetForm = () => {
  caCertFile.value = null
  caKeyFile.value = null
  name.value = ''
  validationErrors.value = []
}

const close = () => {
  resetForm()
  emit('update:visible', false)
}

const submit = async () => {
  validationErrors.value = []
  if (!caCertFile.value) {
    validationErrors.value.push(t('importCa.errorCaCertRequired'))
    return
  }

  const form = new FormData()
  form.append('ca_cert', caCertFile.value)
  if (caKeyFile.value) form.append('ca_key', caKeyFile.value)
  if (name.value.trim()) form.append('name', name.value.trim())

  submitting.value = true
  try {
    await caStore.importCa(form)
    emit('imported')
    close()
  } catch (err: any) {
    const msg = err?.response?.data?.error ?? t('importCa.errorGeneric')
    toast.add({ severity: 'error', summary: t('importCa.errorTitle'), detail: msg, life: 5000 })
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

.vt-input-full {
  width: 100%;
}

.vt-errors {
  background: var(--vt-err, #ef4444);
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
</style>
