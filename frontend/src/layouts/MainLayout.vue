<template>
  <div class="vt-app">
    <Sidebar />
    <main :class="['vt-content', { collapsed }]">
      <router-view />
    </main>
  </div>
</template>

<script setup lang="ts">
import { onMounted } from 'vue'
import Sidebar from '@/components/Sidebar.vue'
import { useSidebar } from '@/composables/useSidebar'
import { useAuthStore } from '@/stores/auth'
import { useSettingsStore } from '@/stores/settings'

const { collapsed } = useSidebar()
const auth = useAuthStore()
const settings = useSettingsStore()

onMounted(async () => {
  if (auth.isAdmin) await settings.fetchSettings()
})
</script>

<style scoped>
.vt-app {
  display: flex;
  min-height: 100vh;
}

.vt-content {
  margin-left: 240px;
  flex: 1;
  padding: 28px 36px;
  transition: margin-left 0.2s;
}

.vt-content.collapsed {
  margin-left: 64px;
}
</style>
