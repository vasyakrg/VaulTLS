<template>
  <div>
    <header class="vt-head">
      <div>
        <h1>{{ $t('profile.title') }}</h1>
        <p class="vt-sub">{{ $t('profile.subtitle') }}</p>
      </div>
      <div class="vt-actions">
        <Button
          :label="$t('common.save')"
          icon="pi pi-check"
          :loading="saving"
          :disabled="!editableUser"
          @click="saveProfile"
        />
      </div>
    </header>

    <div class="vt-section">
      <div class="vt-section-title">{{ $t('settings.user.heading') }}</div>

      <!-- Change Password -->
      <div class="vt-subsection">
        <div class="vt-subsection-title">{{ $t('settings.user.changePassword') }}</div>
        <form class="vt-form" @submit.prevent="changePassword">

          <div v-if="authStore.current_user?.has_password" class="vt-field">
            <label for="old-password">{{ $t('settings.user.oldPassword') }}</label>
            <Password
              id="old-password"
              v-model="changePasswordReq.oldPassword"
              :feedback="false"
              toggleMask
              class="vt-select"
            />
          </div>

          <div class="vt-field">
            <label for="new-password">{{ $t('settings.user.newPassword') }}</label>
            <Password
              id="new-password"
              v-model="changePasswordReq.newPassword"
              :feedback="false"
              toggleMask
              class="vt-select"
            />
          </div>

          <div class="vt-field">
            <label for="confirm-password">{{ $t('settings.user.confirmPassword') }}</label>
            <Password
              id="confirm-password"
              v-model="confirmPassword"
              :feedback="false"
              toggleMask
              class="vt-select"
            />
          </div>

          <div v-if="password_error" class="vt-error">{{ password_error }}</div>

          <Button
            type="submit"
            :label="$t('settings.user.changePassword')"
            :disabled="!canChangePassword"
          />
        </form>
      </div>

      <!-- Profile -->
      <div v-if="editableUser" class="vt-subsection">
        <div class="vt-subsection-title">{{ $t('settings.user.profile') }}</div>
        <div class="vt-form">

          <div class="vt-field">
            <label for="user_name">{{ $t('common.username') }}</label>
            <InputText
              id="user_name"
              v-model="editableUser.name"
            />
          </div>

          <div class="vt-field">
            <label for="user_email">{{ $t('common.email') }}</label>
            <InputText
              id="user_email"
              v-model="editableUser.email"
              type="email"
            />
          </div>
        </div>
      </div>

      <!-- Service Accounts (собственные, доступны любому пользователю) -->
      <div class="vt-subsection">
        <div class="vt-subsection-title">{{ $t('serviceAccounts.title') }}</div>
        <p class="vt-sub">{{ $t('serviceAccounts.selfSubtitle') }}</p>
        <Button
          id="OwnServiceAccountsButton"
          icon="pi pi-key"
          severity="secondary"
          outlined
          :label="$t('serviceAccounts.openButton')"
          @click="isServiceAccountsVisible = true"
        />
      </div>
    </div>

    <ServiceAccountsModal
      v-model:visible="isServiceAccountsVisible"
      :user="current_user ?? null"
    />

    <div v-if="user_error" class="vt-error">{{ user_error }}</div>
    <div v-if="saved_successfully" class="vt-success">{{ $t('settings.savedSuccessfully') }}</div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, onMounted } from 'vue';
import { useAuthStore } from '@/stores/auth';
import { useUserStore } from '@/stores/users.ts';
import type { User } from '@/types/User.ts';
import Button from 'primevue/button';
import InputText from 'primevue/inputtext';
import Password from 'primevue/password';
import ServiceAccountsModal from '@/components/ServiceAccountsModal.vue';

const authStore = useAuthStore();
const userStore = useUserStore();

const current_user = computed(() => authStore.current_user);
const user_error = computed(() => userStore.error);
const password_error = computed(() => authStore.error);

const saving = ref(false);
const saved_successfully = ref(false);
const changePasswordReq = ref({ oldPassword: '', newPassword: '' });
const confirmPassword = ref('');
const editableUser = ref<User | null>(null);
const isServiceAccountsVisible = ref(false);

const canChangePassword = computed(() =>
    changePasswordReq.value.newPassword === confirmPassword.value &&
    changePasswordReq.value.newPassword.length > 0
);

const changePassword = async () => {
  await authStore.changePassword(changePasswordReq.value.oldPassword, changePasswordReq.value.newPassword);
  changePasswordReq.value = { oldPassword: '', newPassword: '' };
  confirmPassword.value = '';
};

const saveProfile = async () => {
  if (!editableUser.value) return;
  saving.value = true;
  saved_successfully.value = false;

  const success = await userStore.updateUser(editableUser.value);
  if (success) {
    await authStore.fetchCurrentUser();
  }

  saved_successfully.value = success;
  saving.value = false;
};

onMounted(() => {
  if (current_user.value) {
    editableUser.value = { ...current_user.value };
  }
});
</script>

<style scoped>
.vt-head {
  display: flex;
  align-items: flex-start;
  margin-bottom: 28px;
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

.vt-section {
  background: var(--vt-card);
  border: 1px solid var(--vt-border);
  border-radius: 10px;
  padding: 18px 20px;
  margin-bottom: 18px;
}

.vt-section-title {
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--vt-muted);
  margin-bottom: 16px;
}

.vt-subsection {
  padding: 14px 0;
  border-top: 1px solid var(--vt-border);
}

.vt-subsection:first-of-type {
  border-top: none;
  padding-top: 0;
}

.vt-subsection-title {
  font-size: 14px;
  font-weight: 600;
  margin-bottom: 12px;
}

.vt-form {
  display: flex;
  flex-direction: column;
  gap: 14px;
  max-width: 460px;
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

.vt-select {
  width: 100%;
}

.vt-error {
  background: var(--vt-err);
  color: #fff;
  padding: 8px 12px;
  border-radius: 6px;
  margin-top: 12px;
  font-size: 13px;
}

.vt-success {
  background: var(--vt-ok);
  color: #fff;
  padding: 8px 12px;
  border-radius: 6px;
  margin-top: 12px;
  font-size: 13px;
}
</style>
