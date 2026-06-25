<template>
  <div>
    <header class="vt-head">
      <div>
        <h1>{{ $t('users.title') }}</h1>
        <p class="vt-sub">{{ $t('users.subtitle') }}</p>
      </div>
      <div class="vt-actions">
        <Button
          id="CreateUserButton"
          :label="$t('users.createUser')"
          icon="pi pi-plus"
          @click="showCreateModal"
        />
      </div>
    </header>

    <div v-if="userStore.loading" class="vt-status">{{ $t('common.loading') }}</div>
    <div v-if="userStore.error" class="vt-error">{{ userStore.error }}</div>

    <DataTable
      :value="userStore.users"
      dataKey="id"
      :globalFilterFields="['name', 'email']"
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

      <Column field="name" :header="$t('common.username')" sortable>
        <template #body="{ data }">
          <span :id="'UserName-' + data.id">{{ data.name }}</span>
        </template>
      </Column>
      <Column field="email" :header="$t('common.email')" sortable>
        <template #body="{ data }">
          <span :id="'UserMail-' + data.id">{{ data.email }}</span>
        </template>
      </Column>
      <Column field="role" :header="$t('users.colRole')" sortable>
        <template #body="{ data }">
          <Tag
            :id="'UserRole-' + data.id"
            :severity="data.role === UserRole.Admin ? 'warn' : 'secondary'"
            :value="data.role === UserRole.Admin ? $t('users.roleAdmin') : $t('users.roleUser')"
          />
        </template>
      </Column>
      <Column :header="$t('common.actions')">
        <template #body="{ data }">
          <div class="vt-row-actions">
            <Button
              :id="'UserEditButton-' + data.id"
              :label="$t('acme.edit')"
              icon="pi pi-pencil"
              severity="secondary"
              outlined
              size="small"
              @click="openEditModal(data)"
            />
            <Button
              :id="'UserDeletebutton-' + data.id"
              :label="$t('common.delete')"
              icon="pi pi-trash"
              severity="danger"
              outlined
              size="small"
              @click="confirmDeleteUser(data)"
            />
          </div>
        </template>
      </Column>

      <template #empty>
        <div class="vt-empty">{{ $t('users.noUsers') }}</div>
      </template>
    </DataTable>

    <!-- Create User Dialog -->
    <BaseModal
      v-model:visible="isCreateModalVisible"
      :title="$t('users.createModal.title')"
      :submitLabel="userStore.loading ? $t('common.creating') : $t('users.createModal.create')"
      submitIcon="pi pi-check"
      :submitDisabled="userStore.loading || !newUser.user_name || !newUser.user_email"
      :loading="userStore.loading"
      @submit="handleCreateUser"
      @cancel="closeCreateModal"
      width="450px"
    >
      <div class="vt-form">
        <div class="vt-field">
          <label>{{ $t('common.username') }}</label>
          <InputText
            v-model="newUser.user_name"
            :placeholder="$t('common.username')"
            class="vt-input-full"
          />
        </div>
        <div class="vt-field">
          <label>{{ $t('common.email') }}</label>
          <InputText
            v-model="newUser.user_email"
            :placeholder="$t('common.email')"
            class="vt-input-full"
          />
        </div>
        <div class="vt-field">
          <label>{{ $t('common.password') }}</label>
          <InputText
            v-model="newUser.password"
            type="password"
            :placeholder="$t('common.password')"
            class="vt-input-full"
          />
        </div>
        <div class="vt-field">
          <label>{{ $t('users.createModal.role') }}</label>
          <Select
            v-model="newUser.role"
            :options="roleOptions"
            optionLabel="label"
            optionValue="value"
            class="vt-select"
          />
        </div>
      </div>
    </BaseModal>

    <!-- Edit User Dialog -->
    <BaseModal
      v-model:visible="isEditModalVisible"
      :title="$t('users.editModal.title')"
      :submitLabel="userStore.loading ? $t('users.editModal.saving') : $t('common.save')"
      submitIcon="pi pi-check"
      :submitDisabled="userStore.loading || !editUser?.name || !editUser?.email"
      :loading="userStore.loading"
      @submit="handleUpdateUser"
      @cancel="closeEditModal"
      width="450px"
    >
      <div class="vt-form" v-if="editUser">
        <div class="vt-field">
          <label>{{ $t('common.username') }}</label>
          <InputText
            v-model="editUser.name"
            :placeholder="$t('common.username')"
            class="vt-input-full"
          />
        </div>
        <div class="vt-field">
          <label>{{ $t('common.email') }}</label>
          <InputText
            v-model="editUser.email"
            :placeholder="$t('common.email')"
            class="vt-input-full"
          />
        </div>
        <div class="vt-field">
          <label>{{ $t('users.createModal.role') }}</label>
          <Select
            v-model="editUser.role"
            :options="roleOptions"
            optionLabel="label"
            optionValue="value"
            class="vt-select"
          />
        </div>
      </div>
    </BaseModal>

    <!-- Delete Confirmation Dialog -->
    <BaseModal
      v-model:visible="isDeleteModalVisible"
      :title="$t('users.deleteModal.title')"
      :submitLabel="$t('common.delete')"
      submitSeverity="danger"
      @submit="deleteUser"
      @cancel="closeDeleteModal"
      width="400px"
    >
      <p>{{ $t('users.deleteModal.confirm', { name: userToDelete?.name }) }}</p>
      <p class="vt-disclaimer">
        <small>{{ $t('users.deleteModal.disclaimer') }}</small>
      </p>
    </BaseModal>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { type CreateUserRequest, UserRole, type User } from '@/types/User'
import { useUserStore } from '@/stores/users.ts'
import { useCertificateStore } from '@/stores/certificates.ts'
import { useI18n } from 'vue-i18n'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Tag from 'primevue/tag'
import Button from 'primevue/button'
import InputText from 'primevue/inputtext'
import Select from 'primevue/select'
import { FilterMatchMode } from '@primevue/core/api'
import BaseModal from '@/components/BaseModal.vue'

const { t } = useI18n()

// stores
const userStore = useUserStore()

// filters
const filters = ref({ global: { value: null, matchMode: FilterMatchMode.CONTAINS } })

// role options
const roleOptions = computed(() => [
  { label: t('users.roleUser'), value: UserRole.User },
  { label: t('users.roleAdmin'), value: UserRole.Admin },
])

// --- Create ---
const isCreateModalVisible = ref(false)
const newUser = ref<CreateUserRequest>({
  user_name: '',
  user_email: '',
  password: '',
  role: UserRole.User,
})

const showCreateModal = () => {
  isCreateModalVisible.value = true
}

const closeCreateModal = () => {
  isCreateModalVisible.value = false
  newUser.value = { user_name: '', user_email: '', password: '', role: UserRole.User }
}

const handleCreateUser = async () => {
  await userStore.createUser(newUser.value)
  if (!userStore.error) {
    closeCreateModal()
  }
}

// --- Edit ---
const isEditModalVisible = ref(false)
const editUser = ref<User | null>(null)

const openEditModal = (user: User) => {
  editUser.value = { ...user }
  isEditModalVisible.value = true
}

const closeEditModal = () => {
  editUser.value = null
  isEditModalVisible.value = false
}

const handleUpdateUser = async () => {
  if (editUser.value) {
    const ok = await userStore.updateUser(editUser.value)
    if (ok) {
      await userStore.fetchUsers(true)
      closeEditModal()
    }
  }
}

// --- Delete ---
const isDeleteModalVisible = ref(false)
const userToDelete = ref<User | null>(null)

const confirmDeleteUser = (user: User) => {
  userToDelete.value = user
  isDeleteModalVisible.value = true
}

const closeDeleteModal = () => {
  userToDelete.value = null
  isDeleteModalVisible.value = false
}

const deleteUser = async () => {
  if (userToDelete.value) {
    await userStore.deleteUser(userToDelete.value.id)
    const certStore = useCertificateStore()
    await certStore.fetchCertificates()
    closeDeleteModal()
  }
}

// lifecycle
onMounted(async () => {
  await userStore.fetchUsers()
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

.vt-select {
  width: 100%;
}

.vt-disclaimer {
  color: var(--vt-muted);
  margin-top: 8px;
}
</style>
