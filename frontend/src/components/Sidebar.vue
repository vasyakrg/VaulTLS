<template>
  <aside :class="['vt-sidebar', { collapsed }]">
    <div
      class="vt-brand"
      @click="toggle"
      v-tooltip.right="$t('sidebar.toggleMenu')"
    >
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

      <a
        :href="apiDocsUrl"
        target="_blank"
        rel="noopener noreferrer"
        class="vt-nav-item"
        v-tooltip.right="collapsed ? $t('sidebar.apiDocs') : ''"
      >
        <i class="pi pi-book" />
        <span v-if="!collapsed">{{ $t('sidebar.apiDocs') }}</span>
      </a>
    </nav>

    <div class="vt-foot">
      <!-- Theme toggle collapsed -->
      <button
        v-if="collapsed"
        class="vt-theme-btn vt-theme-cycle"
        v-tooltip.right="'Тема: ' + themeStore.theme"
        @click="cycleTheme"
      >
        <i :class="themeIcons[themeStore.theme]" />
      </button>

      <!-- Theme toggle -->
      <div v-if="!collapsed" class="vt-theme-row" :class="{ 'vt-theme-row--collapsed': collapsed }">
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

const apiDocsUrl = `${window.location.origin}/api/`

const themes = ['light', 'dark', 'auto'] as const
const themeIcons = { light: 'pi pi-sun', dark: 'pi pi-moon', auto: 'pi pi-desktop' } as const
function cycleTheme() {
  const idx = themes.indexOf(themeStore.theme)
  themeStore.setTheme(themes[(idx + 1) % 3])
}

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
  ...(auth.isLocalAdmin ? [
    { name: 'groups', to: '/groups', icon: 'pi pi-th-large', label: 'sidebar.groups' },
  ] : []),
  ...(auth.isAdmin && settingsStore.settings?.acme.enabled ? [
    { name: 'acme', to: '/acme', icon: 'pi pi-bolt', label: 'sidebar.acme' },
  ] : []),
  ...(auth.isAdmin ? [
    { name: 'letsencrypt', to: '/letsencrypt', icon: 'pi pi-verified', label: 'sidebar.letsencrypt' },
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
  gap: 12px;
  font-weight: 700;
  padding: 9px 11px 18px;
  white-space: nowrap;
  overflow: hidden;
  cursor: pointer;
  border-radius: 9px;
  color: var(--vt-text);
  user-select: none;
}

.vt-brand:hover {
  background: rgba(127, 127, 127, 0.08);
}

.vt-logo {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 18px;
  height: 18px;
  font-size: 18px;
  flex-shrink: 0;
  line-height: 1;
}

.vt-logo-img {
  width: 28px;
  height: 28px;
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

</style>
