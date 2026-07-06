<template>
  <div>
    <header class="vt-head">
      <div>
        <h1>{{ $t('groups.title') }}</h1>
        <p class="vt-sub">{{ $t('groups.subtitle') }}</p>
      </div>
      <div class="vt-actions">
        <Button
          id="CreateGroupButton"
          icon="pi pi-plus"
          v-tooltip.top="$t('groups.create')"
          :aria-label="$t('groups.create')"
          @click="showCreateModal"
        />
      </div>
    </header>

    <div v-if="groupStore.loading" class="vt-status">{{ $t('common.loading') }}</div>
    <div v-if="groupStore.error" class="vt-error">{{ groupStore.error }}</div>

    <DataTable
      :value="groupStore.groups"
      dataKey="id"
      :globalFilterFields="['name', 'description']"
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

      <Column field="name" :header="$t('groups.name')" sortable>
        <template #body="{ data }">
          <span :id="'GroupName-' + data.id">{{ data.name }}</span>
        </template>
      </Column>
      <Column field="description" :header="$t('groups.description')" sortable>
        <template #body="{ data }">
          <span :id="'GroupDescription-' + data.id">{{ data.description }}</span>
        </template>
      </Column>
      <Column :header="$t('common.actions')">
        <template #body="{ data }">
          <div class="vt-row-actions">
            <Button
              :id="'GroupEditButton-' + data.id"
              icon="pi pi-pencil"
              severity="secondary"
              outlined
              size="small"
              v-tooltip.top="$t('groups.edit')"
              :aria-label="$t('groups.edit')"
              @click="openEditModal(data)"
            />
            <Button
              :id="'GroupDeleteButton-' + data.id"
              icon="pi pi-trash"
              severity="danger"
              outlined
              size="small"
              v-tooltip.top="$t('groups.delete')"
              :aria-label="$t('groups.delete')"
              @click="confirmDeleteGroup(data)"
            />
          </div>
        </template>
      </Column>

      <template #empty>
        <div class="vt-empty">{{ $t('groups.empty') }}</div>
      </template>
    </DataTable>

    <!-- Create Group Dialog -->
    <BaseModal
      v-model:visible="isCreateModalVisible"
      :title="$t('groups.createModal.title')"
      :submitLabel="groupStore.loading ? $t('common.creating') : $t('groups.createModal.create')"
      submitIcon="pi pi-check"
      :submitDisabled="groupStore.loading || !form.name"
      :loading="groupStore.loading"
      @submit="handleCreateGroup"
      @cancel="closeCreateModal"
      width="500px"
    >
      <div class="vt-form">
        <div class="vt-field">
          <label>{{ $t('groups.name') }}</label>
          <InputText
            id="group_name"
            v-model="form.name"
            :placeholder="$t('groups.name')"
            class="vt-input-full"
          />
        </div>
        <div class="vt-field">
          <label>{{ $t('groups.description') }}</label>
          <InputText
            id="group_description"
            v-model="form.description"
            :placeholder="$t('groups.description')"
            class="vt-input-full"
          />
        </div>
        <div class="vt-field">
          <label>{{ $t('groups.members') }}</label>
          <MultiSelect
            v-model="selectedUserIds"
            :options="userOptions"
            optionLabel="label"
            optionValue="id"
            display="chip"
            filter
            :placeholder="$t('groups.members')"
            class="vt-input-full"
          />
        </div>
        <div class="vt-field">
          <label>{{ $t('groups.certificates') }}</label>
          <MultiSelect
            v-model="selectedCertIds"
            :options="certificateOptions"
            optionLabel="label"
            optionValue="id"
            display="chip"
            filter
            :placeholder="$t('groups.certificates')"
            class="vt-input-full"
          />
        </div>
      </div>
    </BaseModal>

    <!-- Edit Group Dialog -->
    <BaseModal
      v-model:visible="isEditModalVisible"
      :title="$t('groups.editModal.title')"
      :submitLabel="groupStore.loading ? $t('groups.editModal.saving') : $t('common.save')"
      submitIcon="pi pi-check"
      :submitDisabled="groupStore.loading || !form.name"
      :loading="groupStore.loading"
      @submit="handleUpdateGroup"
      @cancel="closeEditModal"
      width="500px"
    >
      <div class="vt-form" v-if="editingGroup">
        <div class="vt-field">
          <label>{{ $t('groups.name') }}</label>
          <InputText
            v-model="form.name"
            :placeholder="$t('groups.name')"
            class="vt-input-full"
          />
        </div>
        <div class="vt-field">
          <label>{{ $t('groups.description') }}</label>
          <InputText
            v-model="form.description"
            :placeholder="$t('groups.description')"
            class="vt-input-full"
          />
        </div>
        <div class="vt-field">
          <label>{{ $t('groups.members') }}</label>
          <MultiSelect
            v-model="selectedUserIds"
            :options="userOptions"
            optionLabel="label"
            optionValue="id"
            display="chip"
            filter
            :placeholder="$t('groups.members')"
            class="vt-input-full"
          />
        </div>
        <div class="vt-field">
          <label>{{ $t('groups.certificates') }}</label>
          <MultiSelect
            v-model="selectedCertIds"
            :options="certificateOptions"
            optionLabel="label"
            optionValue="id"
            display="chip"
            filter
            :placeholder="$t('groups.certificates')"
            class="vt-input-full"
          />
        </div>
      </div>
    </BaseModal>

    <!-- Delete Confirmation Dialog -->
    <BaseModal
      v-model:visible="isDeleteModalVisible"
      :title="$t('groups.deleteModal.title')"
      :submitLabel="$t('common.delete')"
      submitSeverity="danger"
      @submit="handleDeleteGroup"
      @cancel="closeDeleteModal"
      width="400px"
    >
      <p>{{ $t('groups.deleteModal.confirm', { name: groupToDelete?.name }) }}</p>
    </BaseModal>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import Tooltip from 'primevue/tooltip'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Button from 'primevue/button'
import InputText from 'primevue/inputtext'
import MultiSelect from 'primevue/multiselect'
import { FilterMatchMode } from '@primevue/core/api'
import BaseModal from '@/components/BaseModal.vue'
import { useGroupStore } from '@/stores/groups'
import { useUserStore } from '@/stores/users'
import { useCertificateStore } from '@/stores/certificates'
import type { Group } from '@/types/Group'

const vTooltip = Tooltip

// stores
const groupStore = useGroupStore()
const userStore = useUserStore()
const certStore = useCertificateStore()

// filters
const filters = ref({ global: { value: null, matchMode: FilterMatchMode.CONTAINS } })

// options for multiselects
const userOptions = computed(() =>
  userStore.users.map((u) => ({ id: u.id, label: `${u.name} (${u.email})` })),
)
const certificateOptions = computed(() =>
  Array.from(certStore.certificates.values()).map((c) => ({ id: c.id, label: c.name.cn })),
)

// shared form state
const form = ref({ name: '', description: '' })
const selectedUserIds = ref<number[]>([])
const selectedCertIds = ref<number[]>([])

const resetForm = () => {
  form.value = { name: '', description: '' }
  selectedUserIds.value = []
  selectedCertIds.value = []
}

// --- Create ---
const isCreateModalVisible = ref(false)

const showCreateModal = () => {
  resetForm()
  isCreateModalVisible.value = true
}

const closeCreateModal = () => {
  isCreateModalVisible.value = false
  resetForm()
}

const handleCreateGroup = async () => {
  await groupStore.createGroup({ name: form.value.name, description: form.value.description || null })
  if (!groupStore.error) {
    const created = groupStore.groups.find((g) => g.name === form.value.name)
    if (created) {
      await groupStore.setGroupUsers(created.id, selectedUserIds.value)
      await groupStore.setGroupCertificates(created.id, selectedCertIds.value)
    }
    await groupStore.fetchGroups(true)
    closeCreateModal()
  }
}

// --- Edit ---
const isEditModalVisible = ref(false)
const editingGroup = ref<Group | null>(null)

const openEditModal = async (group: Group) => {
  editingGroup.value = group
  form.value = { name: group.name, description: group.description ?? '' }
  selectedUserIds.value = []
  selectedCertIds.value = []
  isEditModalVisible.value = true
  const detail = await groupStore.fetchGroup(group.id)
  selectedUserIds.value = detail?.user_ids ?? []
  selectedCertIds.value = detail?.certificate_ids ?? []
}

const closeEditModal = () => {
  isEditModalVisible.value = false
  editingGroup.value = null
  resetForm()
}

const handleUpdateGroup = async () => {
  if (!editingGroup.value) return
  const id = editingGroup.value.id
  await groupStore.updateGroup(id, { name: form.value.name, description: form.value.description || null })
  if (!groupStore.error) {
    await groupStore.setGroupUsers(id, selectedUserIds.value)
    await groupStore.setGroupCertificates(id, selectedCertIds.value)
    await groupStore.fetchGroups(true)
    closeEditModal()
  }
}

// --- Delete ---
const isDeleteModalVisible = ref(false)
const groupToDelete = ref<Group | null>(null)

const confirmDeleteGroup = (group: Group) => {
  groupToDelete.value = group
  isDeleteModalVisible.value = true
}

const closeDeleteModal = () => {
  groupToDelete.value = null
  isDeleteModalVisible.value = false
}

const handleDeleteGroup = async () => {
  if (groupToDelete.value) {
    await groupStore.deleteGroup(groupToDelete.value.id)
    closeDeleteModal()
  }
}

// lifecycle
onMounted(async () => {
  await Promise.all([
    groupStore.fetchGroups(true),
    userStore.fetchUsers(),
    certStore.fetchCertificates(),
  ])
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

.vt-input-full {
  width: 100%;
}
</style>
