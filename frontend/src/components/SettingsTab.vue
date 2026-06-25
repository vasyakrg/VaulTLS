<template>
  <div>
    <header class="vt-head">
      <div>
        <h1>{{ $t('settings.title') }}</h1>
        <p class="vt-sub">{{ $t('settings.subtitle') }}</p>
      </div>
      <div class="vt-actions">
        <Button
          :label="$t('common.save')"
          icon="pi pi-check"
          :loading="saving"
          @click="saveSettings"
        />
      </div>
    </header>

    <!-- Admin-only sections -->
    <div v-if="authStore.isAdmin && settings">

      <!-- Common Section -->
      <div class="vt-section">
        <div class="vt-section-title">{{ $t('settings.common.heading') }}</div>
        <div class="vt-form">

          <div class="vt-field vt-switch-field">
            <ToggleSwitch v-model="settings.common.password_enabled" inputId="common-password-enabled" />
            <label for="common-password-enabled">{{ $t('settings.common.passwordEnabled') }}</label>
          </div>

          <div class="vt-field">
            <label for="common-vaultls-url">{{ $t('settings.common.vaultlsUrl') }}</label>
            <InputText
              id="common-vaultls-url"
              v-model="settings.common.vaultls_url"
            />
          </div>

          <div class="vt-field">
            <label for="common-password-rule">{{ $t('settings.common.passwordRule') }}</label>
            <Select
              id="common-password-rule"
              v-model="settings.common.password_rule"
              :options="passwordRuleOptions"
              optionLabel="label"
              optionValue="value"
              class="vt-select"
            />
          </div>

          <div class="vt-field">
            <label for="crl-next-update">{{ $t('settings.common.crlValidity') }}</label>
            <div class="vt-input-group">
              <InputNumber
                id="crl-next-update"
                v-model="crlNextUpdateValue"
                class="vt-input-grow"
                :min="1"
                @update:modelValue="updateCrlNextUpdate"
              />
              <Select
                v-model="crlNextUpdateUnit"
                :options="crlUnitOptions"
                optionLabel="label"
                optionValue="value"
                class="vt-crl-unit"
                @change="updateCrlNextUpdate"
              />
            </div>
          </div>

          <div class="vt-field">
            <label for="common-default-language">{{ $t('settings.common.defaultLanguage') }}</label>
            <Select
              id="common-default-language"
              v-model="settings.common.default_language"
              :options="languageOptions"
              optionLabel="label"
              optionValue="value"
              class="vt-select"
            />
          </div>
        </div>
      </div>

      <!-- Mail Section -->
      <div class="vt-section">
        <div class="vt-section-title">{{ $t('settings.mail.heading') }}</div>
        <div class="vt-form">

          <div class="vt-field vt-field-row">
            <div class="vt-field vt-input-grow">
              <label for="mail-smtp-host">{{ $t('settings.mail.smtpHost') }}</label>
              <InputText
                id="mail-smtp-host"
                v-model="settings.mail.smtp_host"
              />
            </div>
            <div class="vt-field vt-port-field">
              <label for="mail-smtp-port">{{ $t('settings.mail.port') }}</label>
              <InputNumber
                id="mail-smtp-port"
                v-model="settings.mail.smtp_port"
                :min="1"
                :max="65535"
                :useGrouping="false"
              />
            </div>
          </div>

          <div class="vt-field">
            <label for="mail-encryption">{{ $t('settings.mail.encryption') }}</label>
            <Select
              id="mail-encryption"
              v-model="settings.mail.encryption"
              :options="encryptionOptions"
              optionLabel="label"
              optionValue="value"
              class="vt-select"
            />
          </div>

          <div class="vt-field">
            <label for="mail-username">{{ $t('common.username') }}</label>
            <InputText
              id="mail-username"
              v-model="settings.mail.username"
            />
          </div>

          <div class="vt-field">
            <label for="mail-password">{{ $t('common.password') }}</label>
            <Password
              id="mail-password"
              v-model="settings.mail.password"
              :feedback="false"
              toggleMask
              class="vt-select"
            />
          </div>

          <div class="vt-field">
            <label for="mail-from">{{ $t('settings.mail.from') }}</label>
            <InputText
              id="mail-from"
              v-model="settings.mail.from"
              type="email"
            />
          </div>
        </div>
      </div>

      <!-- OIDC Section -->
      <div class="vt-section">
        <div class="vt-section-title">{{ $t('settings.oidc.heading') }}</div>
        <div class="vt-form">

          <div class="vt-field">
            <label for="oidc-id">{{ $t('settings.oidc.clientId') }}</label>
            <InputText
              id="oidc-id"
              v-model="settings.oidc.id"
            />
          </div>

          <div class="vt-field">
            <label for="oidc-secret">{{ $t('settings.oidc.clientSecret') }}</label>
            <Password
              id="oidc-secret"
              v-model="settings.oidc.secret"
              :feedback="false"
              toggleMask
              class="vt-select"
            />
          </div>

          <div class="vt-field">
            <label for="oidc-auth-url">{{ $t('settings.oidc.authUrl') }}</label>
            <InputText
              id="oidc-auth-url"
              v-model="settings.oidc.auth_url"
            />
          </div>

          <div class="vt-field">
            <label for="oidc-callback-url">{{ $t('settings.oidc.callbackUrl') }}</label>
            <InputText
              id="oidc-callback-url"
              v-model="settings.oidc.callback_url"
            />
          </div>
        </div>
      </div>

      <!-- ACME Section -->
      <div class="vt-section">
        <div class="vt-section-title">{{ $t('settings.acme.heading') }}</div>
        <div class="vt-form">

          <div class="vt-field vt-switch-field">
            <ToggleSwitch v-model="settings.acme.enabled" inputId="acme-enabled" />
            <label for="acme-enabled">{{ $t('settings.acme.serverEnabled') }}</label>
          </div>

          <div class="vt-field vt-switch-field">
            <ToggleSwitch v-model="settings.acme.notify_issuance" inputId="notify-acme-issuance" />
            <label for="notify-acme-issuance">{{ $t('settings.acme.notifyIssuance') }}</label>
          </div>

          <div class="vt-field">
            <label for="acme-dns-resolver">{{ $t('settings.acme.dnsResolver') }}</label>
            <InputText
              id="acme-dns-resolver"
              v-model="settings.acme.dns_resolver"
              :placeholder="$t('settings.acme.dnsResolverPlaceholder')"
            />
            <span class="vt-help-text">
              {{ $t('settings.acme.dnsResolverHelp') }}
              <ul class="vt-help-list">
                <li>{{ $t('settings.acme.dnsFormatUdp') }} — <code>8.8.8.8</code></li>
                <li>{{ $t('settings.acme.dnsFormatHttps') }} — <code>https://dns.google/dns-query</code> {{ $t('common.or') }} <code>https://1.1.1.1/dns-query</code></li>
                <li>{{ $t('settings.acme.dnsFormatTls') }} — <code>tls://1.1.1.1</code> {{ $t('common.or') }} <code>tls://8.8.8.8:853#dns.google</code> <i18n-t keypath="settings.acme.optionallyAppend" tag="span"><template #hostname><code>#{{ $t('common.hostname') }}</code></template></i18n-t></li>
              </ul>
            </span>
          </div>

          <div class="vt-field vt-switch-field">
            <ToggleSwitch v-model="settings.acme.accept_invalid_certs" inputId="acme-accept-invalid-certs" />
            <label for="acme-accept-invalid-certs">{{ $t('settings.acme.acceptInvalidCerts') }}</label>
          </div>

          <div class="vt-field vt-switch-field">
            <ToggleSwitch v-model="settings.acme.rate_limit_enabled" inputId="acme-rate-limit-enabled" />
            <label for="acme-rate-limit-enabled">{{ $t('settings.acme.rateLimitEnabled') }}</label>
          </div>

          <div class="vt-field">
            <label for="acme-rate-limit">{{ $t('settings.acme.rateLimit') }}</label>
            <InputNumber
              id="acme-rate-limit"
              v-model="settings.acme.rate_limit"
              :disabled="!settings.acme.rate_limit_enabled"
              placeholder="20"
              :min="1"
              :useGrouping="false"
            />
          </div>
        </div>
      </div>
    </div>

    <!-- User Section -->
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
    </div>

    <!-- Feedback messages -->
    <div v-if="settings_error" class="vt-error">{{ settings_error }}</div>
    <div v-if="user_error" class="vt-error">{{ user_error }}</div>
    <div v-if="saved_successfully" class="vt-success">{{ $t('settings.savedSuccessfully') }}</div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, onMounted } from 'vue';
import { useSettingsStore } from '@/stores/settings';
import { useAuthStore } from '@/stores/auth';
import { type User, UserRole } from "@/types/User.ts";
import { useUserStore } from "@/stores/users.ts";
import { useSetupStore } from "@/stores/setup.ts";
import { Encryption, PasswordRule, type Settings } from "@/types/Settings.ts";
import { SUPPORTED_LOCALES } from '@/plugins/i18n';
import { useI18n } from 'vue-i18n';
import Button from 'primevue/button';
import InputText from 'primevue/inputtext';
import InputNumber from 'primevue/inputnumber';
import Password from 'primevue/password';
import Select from 'primevue/select';
import ToggleSwitch from 'primevue/toggleswitch';

const { t } = useI18n();

// Stores
const settingsStore = useSettingsStore();
const authStore = useAuthStore();
const userStore = useUserStore();
const setupStore = useSetupStore();

// Local copy of settings — not committed to the store until Save is clicked
const settings = ref<Settings | null>(null);
const current_user = computed(() => authStore.current_user);
const settings_error = computed(() => settingsStore.error);
const user_error = computed(() => userStore.error);
const password_error = computed(() => authStore.error);

const canChangePassword = computed(() =>
    changePasswordReq.value.newPassword === confirmPassword.value &&
    changePasswordReq.value.newPassword.length > 0
);

// Local state
const saving = ref(false);
const changePasswordReq = ref({ oldPassword: '', newPassword: '' });
const confirmPassword = ref('');
const editableUser = ref<User | null>(null);
const saved_successfully = ref(false);

const crlNextUpdateValue = ref<number | null>(7);
const crlNextUpdateUnit = ref('days');

// Select options
const passwordRuleOptions = computed(() => [
  { label: t('settings.common.passwordRuleOptional'), value: PasswordRule.Optional },
  { label: t('settings.common.passwordRuleRequired'), value: PasswordRule.Required },
  { label: t('settings.common.passwordRuleSystem'), value: PasswordRule.System },
]);

const crlUnitOptions = computed(() => [
  { label: t('settings.common.crlHours'), value: 'hours' },
  { label: t('settings.common.crlDays'), value: 'days' },
  { label: t('settings.common.crlWeeks'), value: 'weeks' },
]);

const languageOptions = computed(() =>
  Object.entries(SUPPORTED_LOCALES).map(([code, label]) => ({ label, value: code }))
);

const encryptionOptions = computed(() => [
  { label: t('settings.mail.encryptionNone'), value: Encryption.None },
  { label: t('settings.mail.encryptionTls'), value: Encryption.TLS },
  { label: t('settings.mail.encryptionStarttls'), value: Encryption.STARTTLS },
]);

const updateCrlNextUpdate = () => {
  if (settings.value) {
    let multiplier = 1;
    if (crlNextUpdateUnit.value === 'days') multiplier = 24;
    else if (crlNextUpdateUnit.value === 'weeks') multiplier = 168;
    settings.value.common.crl_next_update_hours = (crlNextUpdateValue.value ?? 1) * multiplier;
  }
};

// Methods
const changePassword = async () => {
  await authStore.changePassword(changePasswordReq.value.oldPassword, changePasswordReq.value.newPassword);
  changePasswordReq.value = { oldPassword: '', newPassword: '' };
  confirmPassword.value = '';
};

const saveSettings = async () => {
  saving.value = true;
  saved_successfully.value = false;
  let success = true;

  if (current_user.value?.role === UserRole.Admin && settings.value) {
    settingsStore.$patch({ settings: JSON.parse(JSON.stringify(settings.value)) });
    success &&= await settingsStore.saveSettings();
    await setupStore.reload();
  }

  if (editableUser.value) {
    success &&= await userStore.updateUser(editableUser.value);
    await authStore.fetchCurrentUser();
  }

  saved_successfully.value = success;
  saving.value = false;
};

onMounted(async () => {
  if (authStore.isAdmin) {
    await settingsStore.fetchSettings();
    if (settingsStore.settings) {
      settings.value = JSON.parse(JSON.stringify(settingsStore.settings));
    }
    if (settings.value) {
      const hours = settings.value.common.crl_next_update_hours;
      if (hours % 168 === 0) {
        crlNextUpdateUnit.value = 'weeks';
        crlNextUpdateValue.value = hours / 168;
      } else if (hours % 24 === 0) {
        crlNextUpdateUnit.value = 'days';
        crlNextUpdateValue.value = hours / 24;
      } else {
        crlNextUpdateUnit.value = 'hours';
        crlNextUpdateValue.value = hours;
      }
    }
  }
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
  border: 1px solid var(--vt-border);
  border-radius: 8px;
  margin-bottom: 20px;
  overflow: hidden;
}

.vt-section-title {
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--vt-muted);
  padding: 10px 16px;
  border-bottom: 1px solid var(--vt-border);
  background: color-mix(in srgb, var(--vt-border) 30%, transparent);
}

.vt-subsection {
  padding: 16px;
  border-bottom: 1px solid var(--vt-border);
}

.vt-subsection:last-child {
  border-bottom: none;
}

.vt-subsection-title {
  font-size: 13px;
  font-weight: 600;
  color: var(--vt-text);
  margin-bottom: 14px;
}

.vt-form {
  display: flex;
  flex-direction: column;
  gap: 14px;
  padding: 16px;
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

.vt-switch-field {
  flex-direction: row;
  align-items: center;
  gap: 10px;
}

.vt-switch-field label {
  color: var(--vt-text);
}

.vt-field-row {
  flex-direction: row;
  gap: 12px;
  align-items: flex-end;
}

.vt-input-grow {
  flex: 1;
}

.vt-port-field {
  width: 110px;
  flex-shrink: 0;
}

.vt-select {
  width: 100%;
}

.vt-crl-unit {
  width: 130px;
}

.vt-input-group {
  display: flex;
  gap: 8px;
  align-items: center;
}

.vt-help-text {
  font-size: 12px;
  color: var(--vt-muted);
  margin-top: 4px;
}

.vt-help-list {
  margin: 6px 0 0 0;
  padding-left: 18px;
}

.vt-help-list li {
  margin-bottom: 3px;
}

.vt-error {
  background: var(--vt-err);
  color: #fff;
  padding: 8px 12px;
  border-radius: 6px;
  margin-bottom: 12px;
  font-size: 13px;
}

.vt-success {
  background: var(--vt-ok);
  color: #fff;
  padding: 8px 12px;
  border-radius: 6px;
  margin-top: 8px;
  font-size: 13px;
}
</style>
