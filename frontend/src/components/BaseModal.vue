<template>
  <Dialog
    :visible="visible"
    @update:visible="onVisibilityChange"
    :header="title"
    modal
    :closable="true"
    :dismissableMask="true"
    :draggable="false"
    :closeOnEscape="true"
    :style="{ width: width }"
    @show="onShow"
    @hide="onHide"
    @keydown="onKeydown"
  >
    <slot />

    <template v-if="!hideFooter" #footer>
      <slot name="footer">
        <Button
          :label="$t('common.cancel')"
          severity="secondary"
          outlined
          @click="handleCancel"
        />
        <Button
          :id="submitId"
          :label="resolvedSubmitLabel"
          :icon="submitIcon"
          :disabled="submitDisabled || loading"
          :loading="loading"
          :severity="submitSeverity"
          @click="handleSubmit"
        />
      </slot>
    </template>
  </Dialog>
</template>

<script setup lang="ts">
import { computed, ref, useSlots } from 'vue'
import { useI18n } from 'vue-i18n'
import Dialog from 'primevue/dialog'
import Button from 'primevue/button'

const props = withDefaults(
  defineProps<{
    visible: boolean
    title: string
    submitLabel?: string
    submitIcon?: string
    submitDisabled?: boolean
    loading?: boolean
    submitSeverity?: string
    hideFooter?: boolean
    width?: string
    submitId?: string
  }>(),
  {
    submitIcon: undefined,
    submitDisabled: false,
    loading: false,
    submitSeverity: undefined,
    hideFooter: false,
    width: '480px',
    submitId: undefined,
  },
)

const emit = defineEmits<{
  (e: 'update:visible', v: boolean): void
  (e: 'submit'): void
  (e: 'cancel'): void
}>()

const { t } = useI18n()
const slots = useSlots()

const isSubmitting = ref(false)

const resolvedSubmitLabel = computed(() => props.submitLabel ?? t('common.save'))

const onVisibilityChange = (v: boolean) => {
  emit('update:visible', v)
}

// Single cancel path: fired by PrimeVue's @hide (covers X, Esc, mask, Cancel button)
// Submit path resets the flag so cancel is not emitted after submit.
const onHide = () => {
  if (!isSubmitting.value) {
    emit('cancel')
  }
  isSubmitting.value = false
}

const handleCancel = () => {
  emit('update:visible', false)
}

const handleSubmit = () => {
  isSubmitting.value = true
  emit('submit')
}

const onShow = () => {
  // focus first focusable input in the dialog content
  setTimeout(() => {
    const dialog = document.querySelector('.p-dialog:not([aria-hidden="true"])')
    if (!dialog) return
    const focusable = dialog.querySelector<HTMLElement>(
      'input:not([type="hidden"]):not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
    )
    focusable?.focus()
  }, 50)
}

const onKeydown = (e: KeyboardEvent) => {
  if (e.key !== 'Enter') return
  const target = e.target as HTMLElement
  // don't intercept Enter inside textarea or contenteditable
  if (target.tagName === 'TEXTAREA' || target.isContentEditable) return
  // don't intercept Enter on buttons (let them click naturally)
  if (target.tagName === 'BUTTON') return
  if (props.submitDisabled || props.loading) return
  e.preventDefault()
  emit('submit')
}
</script>
