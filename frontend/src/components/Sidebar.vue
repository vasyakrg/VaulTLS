<template>
  <aside :class="['vt-sidebar', { collapsed }]">
    <div class="vt-brand">
      <span class="vt-logo">🔐</span>
      <span v-if="!collapsed">VaulTLS</span>
    </div>

    <nav class="vt-nav">
      <RouterLink
        v-for="item in items"
        :key="item.name"
        :to="item.to"
        class="vt-nav-item"
        v-tooltip.right="collapsed ? $t(item.label) : ''"
      >
        <i :class="item.icon" />
        <span v-if="!collapsed">{{ $t(item.label) }}</span>
      </RouterLink>
    </nav>

    <div class="vt-foot">
      <!-- Theme toggle -->
      <div class="vt-theme-row" :class="{ 'vt-theme-row--collapsed': collapsed }">
        <button
          class="vt-theme-btn"
          :class="{ active: themeStore.theme === 'light' }"
          @click="themeStore.setTheme('light')"
          v-tooltip.right="collapsed ? $t('sidebar.lightMode') : ''"
          :title="!collapsed ? $t('sidebar.lightMode') : ''"
        >
          <i class="pi pi-sun" />
        </button>
        <button
          class="vt-theme-btn"
          :class="{ active: themeStore.theme === 'dark' }"
          @click="themeStore.setTheme('dark')"
          v-tooltip.right="collapsed ? $t('sidebar.darkMode') : ''"
          :title="!collapsed ? $t('sidebar.darkMode') : ''"
        >
          <i class="pi pi-moon" />
        </button>
        <button
          v-if="!collapsed"
          class="vt-theme-btn"
          :class="{ active: themeStore.theme === 'auto' }"
          @click="themeStore.setTheme('auto')"
          :title="$t('sidebar.autoMode')"
        >
          <i class="pi pi-desktop" />
        </button>
      </div>

      <!-- Language selector -->
      <div v-if="!collapsed" class="vt-lang-row">
        <select
          class="vt-lang-select"
          :value="locale"
          @change="changeLocale(($event.target as HTMLSelectElement).value)"
        >
          <option v-for="(label, code) in SUPPORTED_LOCALES" :key="code" :value="code">
            {{ label }}
          </option>
        </select>
      </div>

      <!-- Logout -->
      <button class="vt-logout" @click="handleLogout" v-tooltip.right="collapsed ? $t('sidebar.logout') : ''">
        <i class="pi pi-sign-out" />
        <span v-if="!collapsed">{{ $t('sidebar.logout') }}</span>
      </button>

      <!-- Version -->
      <div v-if="!collapsed" class="vt-version">
        {{ $t('sidebar.version', { version: setupStore.version }) }}
      </div>

      <!-- Profile card -->
      <ProfileCard v-if="!collapsed" />

      <!-- Collapse toggle -->
      <button class="vt-collapse" @click="toggle">
        <i :class="collapsed ? 'pi pi-angle-right' : 'pi pi-angle-left'" />
      </button>
    </div>
  </aside>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { RouterLink, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import Tooltip from 'primevue/tooltip'
import ProfileCard from '@/components/ProfileCard.vue'
import { useSidebar } from '@/composables/useSidebar'
import { useAuthStore } from '@/stores/auth'
import { useSettingsStore } from '@/stores/settings'
import { useSetupStore } from '@/stores/setup'
import { useThemeStore } from '@/stores/theme'
import { SUPPORTED_LOCALES } from '@/plugins/i18n'

const vTooltip = Tooltip

const { collapsed, toggle } = useSidebar()
const auth = useAuthStore()
const settingsStore = useSettingsStore()
const setupStore = useSetupStore()
const themeStore = useThemeStore()
const router = useRouter()
const { locale } = useI18n()

const changeLocale = (lang: string) => {
  locale.value = lang
  localStorage.setItem('locale', lang)
}

const handleLogout = async () => {
  await auth.logout()
  router.push({ name: 'Login' })
}

const items = computed(() => [
  { name: 'overview', to: '/overview', icon: 'pi pi-shield', label: 'sidebar.overview' },
  { name: 'ca', to: '/ca', icon: 'pi pi-building-columns', label: 'sidebar.ca' },
  ...(auth.isAdmin ? [
    { name: 'users', to: '/users', icon: 'pi pi-users', label: 'sidebar.users' },
  ] : []),
  ...(auth.isAdmin && settingsStore.settings?.acme.enabled ? [
    { name: 'acme', to: '/acme', icon: 'pi pi-bolt', label: 'sidebar.acme' },
  ] : []),
  { name: 'settings', to: '/settings', icon: 'pi pi-cog', label: 'sidebar.settings' },
])
</script>

<style scoped>
.vt-sidebar {
  width: 240px;
  background: var(--vt-surface);
  border-right: 1px solid var(--vt-border);
  display: flex;
  flex-direction: column;
  height: 100vh;
  position: fixed;
  top: 0;
  left: 0;
  transition: width 0.2s;
  padding: 14px 10px;
  z-index: 100;
  overflow: hidden;
}

.vt-sidebar.collapsed {
  width: 64px;
}

.vt-brand {
  display: flex;
  align-items: center;
  gap: 10px;
  font-weight: 700;
  padding: 8px 8px 18px;
  white-space: nowrap;
  overflow: hidden;
}

.vt-logo {
  font-size: 20px;
  flex-shrink: 0;
}

.vt-nav {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.vt-nav-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 9px 11px;
  border-radius: 9px;
  color: var(--vt-muted);
  text-decoration: none;
  font-size: 14px;
  font-weight: 500;
  white-space: nowrap;
  overflow: hidden;
}

.vt-nav-item:hover {
  background: rgba(127, 127, 127, 0.08);
  color: var(--vt-text);
}

.vt-nav-item.router-link-active {
  background: color-mix(in srgb, var(--vt-primary) 16%, transparent);
  color: var(--vt-primary);
}

.vt-foot {
  margin-top: auto;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.vt-theme-row {
  display: flex;
  gap: 4px;
}

.vt-theme-btn {
  background: transparent;
  border: 1px solid var(--vt-border);
  border-radius: 6px;
  color: var(--vt-muted);
  padding: 5px 8px;
  cursor: pointer;
  flex: 1;
  font-size: 13px;
}

.vt-theme-btn.active {
  background: color-mix(in srgb, var(--vt-primary) 16%, transparent);
  color: var(--vt-primary);
  border-color: var(--vt-primary);
}

.vt-lang-row {
  display: flex;
}

.vt-lang-select {
  width: 100%;
  background: transparent;
  border: 1px solid var(--vt-border);
  border-radius: 6px;
  color: var(--vt-text);
  padding: 5px 8px;
  font-size: 13px;
  cursor: pointer;
}

.vt-logout {
  display: flex;
  align-items: center;
  gap: 10px;
  width: 100%;
  background: transparent;
  border: none;
  color: var(--vt-muted);
  padding: 7px 11px;
  border-radius: 8px;
  font-size: 14px;
  cursor: pointer;
  text-align: left;
  white-space: nowrap;
  overflow: hidden;
}

.vt-logout:hover {
  background: rgba(127, 127, 127, 0.08);
  color: var(--vt-text);
}

.vt-version {
  font-size: 11px;
  color: var(--vt-muted);
  text-align: center;
  padding: 2px 0;
  white-space: nowrap;
  overflow: hidden;
}

.vt-collapse {
  background: transparent;
  border: 1px solid var(--vt-border);
  border-radius: 8px;
  color: var(--vt-muted);
  padding: 6px;
  cursor: pointer;
  align-self: flex-start;
}

.vt-collapse:hover {
  color: var(--vt-text);
}
</style>
