<template>
  <div class="auth-wrapper">
    <Card class="setup-card">
      <template #content>
        <div class="setup-header">
          <img src="/favicon.ico" alt="VaulTLS" class="setup-logo-img" />
          <h2 class="setup-title">{{ $t('setup.hello') }}</h2>
        </div>

        <div class="setup-lang-row">
          <span class="auth-label">{{ $t('settings.common.defaultLanguage') }}</span>
          <Select
            :model-value="locale"
            :options="localeOptions"
            option-label="label"
            option-value="value"
            class="setup-lang-select"
            @change="changeLocale($event.value)"
          />
        </div>

        <Message v-if="setupStore.oidcUrl" severity="info" :closable="false" class="setup-notice">
          {{ $t('setup.oidcNotice') }}
        </Message>

        <Message v-if="errorMessage" severity="error" :closable="false" class="setup-notice">
          {{ errorMessage }}
        </Message>

        <form @submit.prevent="setupPassword" class="setup-form">
          <div class="setup-section-label">{{ $t('setup.sectionAccount') }}</div>

          <div class="auth-field">
            <label for="username" class="auth-label">{{ $t('common.username') }}</label>
            <InputText id="username" v-model="username" class="w-full" required />
          </div>

          <div class="auth-field">
            <label for="email" class="auth-label">{{ $t('common.email') }}</label>
            <InputText id="email" v-model="email" type="email" class="w-full" required />
          </div>

          <div class="setup-section-label" style="margin-top: 1.25rem;">{{ $t('setup.sectionCa') }}</div>

          <div class="auth-field">
            <label for="ca_name" class="auth-label">{{ $t('setup.caName') }}</label>
            <InputText id="ca_name" v-model="ca_name" class="w-full" required />
          </div>

          <div class="auth-field">
            <label for="ca_validity_duration" class="auth-label">{{ $t('setup.caValidity') }}</label>
            <div class="setup-validity-row">
              <InputNumber
                id="ca_validity_duration"
                v-model="ca_validity_duration"
                class="setup-validity-number"
                :min="1"
                required
              />
              <Select
                v-model="ca_validity_unit"
                :options="validityUnitOptions"
                option-label="label"
                option-value="value"
                class="setup-validity-unit"
              />
            </div>
          </div>

          <div class="setup-section-label" style="margin-top: 1.25rem;">{{ $t('setup.sectionSecurity') }}</div>

          <div class="auth-field">
            <label for="password" class="auth-label">{{ $t('common.password') }}</label>
            <Password
              input-id="password"
              v-model="password"
              class="w-full"
              input-class="w-full"
              autocomplete="new-password"
              :required="!setupStore.oidcUrl"
              :feedback="true"
              toggle-mask
            />
            <small class="setup-hint">
              {{ setupStore.oidcUrl ? $t('setup.passwordHintOidc') : $t('setup.passwordHintRequired') }}
            </small>
          </div>

          <Button
            type="submit"
            :label="$t('setup.completeSetup')"
            class="setup-submit-btn"
            :loading="loading"
          />
        </form>
      </template>
    </Card>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue';
import { useI18n } from 'vue-i18n';
import Card from 'primevue/card';
import InputText from 'primevue/inputtext';
import Password from 'primevue/password';
import Button from 'primevue/button';
import Message from 'primevue/message';
import Select from 'primevue/select';
import InputNumber from 'primevue/inputnumber';
import { SUPPORTED_LOCALES } from '@/plugins/i18n';
import router from '../router/router';
import { setup } from '@/api/auth.ts';
import { useSetupStore } from '@/stores/setup.ts';
import { hashPassword } from '@/utils/hash.ts';
import { ValidityUnit } from '@/types/ValidityUnit.ts';

const { t, locale } = useI18n();

const changeLocale = (lang: string) => {
  locale.value = lang;
  localStorage.setItem('locale', lang);
};

const localeOptions = computed(() =>
  Object.entries(SUPPORTED_LOCALES).map(([value, label]) => ({ value, label }))
);

const validityUnitOptions = computed(() => [
  { value: ValidityUnit.Hour, label: t('common.hours') },
  { value: ValidityUnit.Day, label: t('common.days') },
  { value: ValidityUnit.Month, label: t('common.months') },
  { value: ValidityUnit.Year, label: t('common.years') },
]);

const setupStore = useSetupStore();

const username = ref('');
const email = ref('');
const ca_name = ref('');
const ca_validity_duration = ref(10);
const ca_validity_unit = ref(ValidityUnit.Year);
const password = ref('');
const errorMessage = ref('');
const loading = ref(false);

const setupPassword = async () => {
  errorMessage.value = '';
  loading.value = true;
  try {
    let hash = password.value ? await hashPassword(password.value) : null;

    await setup({
      name: username.value,
      email: email.value,
      ca_name: ca_name.value,
      validity_duration: ca_validity_duration.value,
      validity_unit: ca_validity_unit.value,
      password: password.value || null,
      default_language: locale.value,
    });
    await setupStore.reload();
    await router.replace({ name: 'Login' });
  } catch (err) {
    errorMessage.value = t('setup.setupFailed');
  } finally {
    loading.value = false;
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
  padding: 1.5rem 1rem;
}

.setup-card {
  width: 100%;
  max-width: 460px;
  background: var(--vt-card, var(--p-surface-900));
  border: 1px solid var(--vt-border, var(--p-surface-700));
  border-radius: 12px;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.32);
}

.setup-header {
  display: flex;
  align-items: center;
  gap: 0.6rem;
  margin-bottom: 1.5rem;
}

.setup-logo-img {
  width: 28px;
  height: 28px;
  object-fit: contain;
}

.setup-title {
  font-size: 1.25rem;
  font-weight: 600;
  color: var(--vt-text, var(--p-text-color));
  margin: 0;
  letter-spacing: -0.02em;
}

.setup-lang-row {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 0.5rem;
  margin-bottom: 1rem;
}

.setup-lang-select {
  width: 130px;
}

.setup-notice {
  margin-bottom: 1rem;
}

.setup-form {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.setup-section-label {
  font-size: 0.6875rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--vt-muted, var(--p-text-muted-color));
  margin-top: 0.25rem;
}

.auth-field {
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
}

.auth-label {
  font-size: 0.8125rem;
  font-weight: 500;
  color: var(--vt-muted, var(--p-text-muted-color));
}

.setup-validity-row {
  display: flex;
  gap: 0.5rem;
}

.setup-validity-number {
  flex: 1;
}

.setup-validity-unit {
  width: 130px;
}

.setup-hint {
  font-size: 0.75rem;
  color: var(--vt-muted, var(--p-text-muted-color));
}

:deep(.w-full .p-password) {
  width: 100%;
}

:deep(.w-full .p-password-input) {
  width: 100%;
}

.setup-submit-btn {
  width: 100%;
  margin-top: 0.75rem;
  justify-content: center;
}
</style>
