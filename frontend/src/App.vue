<!-- src/App.vue -->
<template>
  <Toast />
  <router-view />
</template>

<script setup lang="ts">
import { onMounted } from 'vue';
import { useThemeStore } from '@/stores/theme';
import Toast from 'primevue/toast';

const themeStore = useThemeStore();

onMounted(() => {
  themeStore.applyTheme();
});
</script>

<style scoped>
/* Global or top-level styles here */
</style>
