<template>
  <BaseModal
    :visible="visible"
    :title="$t('serviceAccounts.title')"
    hideFooter
    width="640px"
    @update:visible="(v: boolean) => emit('update:visible', v)"
    @cancel="onClose"
  >
    <p class="vt-sub">{{ $t('serviceAccounts.subtitle', { name: user?.name }) }}</p>

    <!-- One-time secret panel -->
    <div v-if="store.lastCreated" class="vt-secret-panel">
      <strong>{{ $t('serviceAccounts.secretTitle') }}</strong>
      <p class="vt-warn">{{ $t('serviceAccounts.secretWarning') }}</p>
      <div class="vt-secret-row">
        <span class="vt-mono">{{ $t('serviceAccounts.clientId') }}:</span>
        <code>{{ store.lastCreated.client_id }}</code>
        <button class="vt-icon-btn" @click="copy(store.lastCreated.client_id, 'cid')">
          <i :class="copied === 'cid' ? 'pi pi-check' : 'pi pi-copy'" />
        </button>
      </div>
      <div class="vt-secret-row">
        <span class="vt-mono">secret:</span>
        <code>{{ store.lastCreated.secret }}</code>
        <button class="vt-icon-btn" @click="copy(store.lastCreated.secret, 'secret')">
          <i :class="copied === 'secret' ? 'pi pi-check' : 'pi pi-copy'" />
        </button>
      </div>
      <Button :label="$t('common.save')" size="small" @click="store.clearLastCreated()" />
    </div>

    <!-- Create form -->
    <div v-else class="vt-create-form">
      <InputText v-model="newName" :placeholder="$t('serviceAccounts.name')" class="vt-input-full" />
      <label class="vt-checkbox-label">
        <input v-model="scopeRead" type="checkbox" class="vt-checkbox" />
        {{ $t('serviceAccounts.scopeCertRead') }}
      </label>
      <label class="vt-checkbox-label">
        <input v-model="scopeIssue" type="checkbox" class="vt-checkbox" />
        {{ $t('serviceAccounts.scopeCertIssue') }}
      </label>
      <Button
        :label="$t('serviceAccounts.create')"
        icon="pi pi-plus"
        :disabled="!newName || (!scopeRead && !scopeIssue) || store.loading"
        @click="onCreate"
      />
    </div>

    <div v-if="store.error" class="vt-error">{{ store.error }}</div>

    <!-- List -->
    <DataTable :value="store.accounts" dataKey="id" class="vt-table">
      <Column field="name" :header="$t('serviceAccounts.name')" />
      <Column field="client_id" :header="$t('serviceAccounts.clientId')" />
      <Column :header="$t('serviceAccounts.scopes')">
        <template #body="{ data }">
          <Tag v-for="s in data.scopes" :key="s" :value="s" severity="secondary" />
        </template>
      </Column>
      <Column :header="$t('serviceAccounts.status')">
        <template #body="{ data }">
          <Tag
            :value="data.revoked ? $t('serviceAccounts.revoked') : $t('serviceAccounts.active')"
            :severity="data.revoked ? 'danger' : 'success'"
          />
        </template>
      </Column>
      <Column :header="$t('common.actions')">
        <template #body="{ data }">
          <Button
            v-if="!data.revoked"
            :label="$t('serviceAccounts.revoke')"
            icon="pi pi-ban"
            severity="danger"
            outlined
            size="small"
            @click="onRevoke(data.id)"
          />
          <Button
            v-else
            :label="$t('common.delete')"
            icon="pi pi-trash"
            severity="danger"
            size="small"
            @click="onDelete(data.id)"
          />
        </template>
      </Column>
      <template #empty>
        <div class="vt-empty">{{ $t('serviceAccounts.noAccounts') }}</div>
      </template>
    </DataTable>
  </BaseModal>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue'
import BaseModal from '@/components/BaseModal.vue'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Tag from 'primevue/tag'
import Button from 'primevue/button'
import InputText from 'primevue/inputtext'
import { useServiceAccountStore } from '@/stores/serviceAccounts'
import type { User } from '@/types/User'

const props = defineProps<{ visible: boolean; user: User | null }>()
const emit = defineEmits<{ 'update:visible': [boolean] }>()

const store = useServiceAccountStore()
const newName = ref('')
const scopeRead = ref(true)
const scopeIssue = ref(false)
const copied = ref<string | null>(null)

watch(
  () => props.visible,
  (open) => {
    if (open && props.user) {
      store.clearLastCreated()
      newName.value = ''
      scopeRead.value = true
      scopeIssue.value = false
      store.fetchForUser(props.user.id)
    }
  },
)

const onCreate = async () => {
  if (!props.user) return
  const scopes: string[] = []
  if (scopeRead.value) scopes.push('cert:read')
  if (scopeIssue.value) scopes.push('cert:issue')
  await store.create(props.user.id, { name: newName.value, scopes })
  newName.value = ''
}

const onRevoke = async (id: number) => {
  if (props.user) await store.revoke(props.user.id, id)
}

const onDelete = async (id: number) => {
  if (props.user) await store.remove(props.user.id, id)
}

const onClose = () => {
  store.clearLastCreated()
  emit('update:visible', false)
}

const copy = async (text: string, which: string) => {
  try {
    await navigator.clipboard.writeText(text)
    copied.value = which
    setTimeout(() => (copied.value = null), 1500)
  } catch (err) {
    console.error('Failed to copy to clipboard: ', err)
  }
}
</script>

<style scoped>
.vt-create-form { display: flex; flex-direction: column; gap: 12px; margin: 12px 0; }
.vt-input-full { width: 100%; }
.vt-checkbox-label { display: flex; align-items: center; gap: 8px; font-size: 14px; }
.vt-secret-panel { border: 1px solid var(--vt-border); border-radius: 8px; padding: 14px; margin: 12px 0; }
.vt-secret-row { display: flex; align-items: center; gap: 8px; margin: 6px 0; }
.vt-secret-row code { background: rgba(127,127,127,0.12); padding: 2px 6px; border-radius: 4px; word-break: break-all; }
.vt-warn { color: var(--vt-muted); font-size: 13px; }
.vt-icon-btn { background: transparent; border: none; cursor: pointer; color: var(--vt-muted); }
.vt-error { background: var(--vt-err); color: #fff; padding: 8px 12px; border-radius: 6px; margin: 8px 0; font-size: 13px; }
.vt-empty { text-align: center; padding: 16px; color: var(--vt-muted); font-style: italic; }
.vt-sub { color: var(--vt-muted); font-size: 13px; margin-bottom: 8px; }
.vt-table { margin-top: 12px; }
</style>
