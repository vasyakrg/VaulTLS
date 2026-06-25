<template>
  <div class="auth-wrapper">
    <Card class="auth-card">
      <template #content>
        <div class="auth-logo">
          <img src="/favicon.ico" alt="VaulTLS" class="auth-logo-img" />
          <span class="auth-logo-name">VaulTLS</span>
        </div>

        <form v-if="setupStore.passwordAuthEnabled" @submit.prevent="submitLogin" class="auth-form">
          <div class="auth-field">
            <label for="email" class="auth-label">{{ $t('common.email') }}</label>
            <InputText
              id="email"
              v-model="email"
              type="email"
              class="auth-input"
              autocomplete="email"
              required
            />
          </div>

          <div class="auth-field">
            <label for="password" class="auth-label">{{ $t('common.password') }}</label>
            <Password
              id="password"
              v-model="password"
              class="auth-input"
              input-class="auth-input"
              autocomplete="current-password"
              :feedback="false"
              toggle-mask
              required
            />
          </div>

          <Message v-if="loginError" severity="error" :closable="false" class="auth-error">
            {{ loginError }}
          </Message>

          <Button
            type="submit"
            :label="$t('login.loginButton')"
            class="auth-btn"
            :loading="loading"
          />
        </form>

        <Message v-else severity="warn" :closable="false" class="auth-error">
          {{ $t('login.noPasswordAuth') }}
        </Message>

        <div v-if="setupStore.oidcUrl" class="auth-divider">
          <span class="auth-divider-text">{{ $t('common.or') }}</span>
        </div>

        <Button
          v-if="setupStore.oidcUrl"
          :label="$t('login.loginWithOAuth')"
          icon="pi pi-sign-in"
          class="auth-btn auth-btn-secondary"
          outlined
          @click="redirectToOIDC"
        />
      </template>
    </Card>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import { useI18n } from 'vue-i18n';
import Card from 'primevue/card';
import InputText from 'primevue/inputtext';
import Password from 'primevue/password';
import Button from 'primevue/button';
import Message from 'primevue/message';
import { useAuthStore } from '../stores/auth';
import { useSetupStore } from '@/stores/setup.ts';
import router from '@/router/router.ts';

const { t } = useI18n();
const email = ref('');
const password = ref('');
const loginError = ref('');
const loading = ref(false);
const authStore = useAuthStore();
const setupStore = useSetupStore();

const submitLogin = async () => {
  loginError.value = '';
  loading.value = true;
  try {
    const success = await authStore.login(email.value, password.value);
    if (!success) {
      loginError.value = t('login.loginFailed');
    } else {
      await router.push('Overview');
    }
  } finally {
    loading.value = false;
  }
};

const redirectToOIDC = () => {
  if (setupStore.oidcUrl) {
    window.location.href = `${window.location.origin}/api/auth/oidc/login`;
  }
};
</script>

<style scoped>
.auth-wrapper {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--vt-bg, var(--p-surface-950));
  padding: 1rem;
}

.auth-card {
  width: 100%;
  max-width: 400px;
  background: var(--vt-card, var(--p-surface-900));
  border: 1px solid var(--vt-border, var(--p-surface-700));
  border-radius: 12px;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.32);
}

.auth-logo {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.6rem;
  margin-bottom: 2rem;
}

.auth-logo-img {
  width: 32px;
  height: 32px;
  object-fit: contain;
}

.auth-logo-name {
  font-size: 1.25rem;
  font-weight: 600;
  color: var(--vt-text, var(--p-text-color));
  letter-spacing: -0.02em;
}

.auth-form {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.auth-field {
  display: flex;
  flex-direction: column;
  gap: 0.4rem;
}

.auth-label {
  font-size: 0.8125rem;
  font-weight: 500;
  color: var(--vt-muted, var(--p-text-muted-color));
}

.auth-input {
  width: 100%;
}

:deep(.auth-input .p-password) {
  width: 100%;
}

:deep(.auth-input .p-password-input) {
  width: 100%;
}

.auth-error {
  margin: 0.25rem 0;
}

.auth-btn {
  width: 100%;
  margin-top: 0.5rem;
  justify-content: center;
}

.auth-btn-secondary {
  margin-top: 0;
}

.auth-divider {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  margin: 1rem 0;
  color: var(--vt-muted, var(--p-text-muted-color));
  font-size: 0.75rem;
}

.auth-divider::before,
.auth-divider::after {
  content: '';
  flex: 1;
  height: 1px;
  background: var(--vt-border, var(--p-surface-700));
}
</style>
