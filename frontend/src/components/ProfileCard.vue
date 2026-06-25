<template>
  <div class="card">
    <Avatar
        :size="100"
        :name="authStore.current_user?.name || 'User'"
        variant="bauhaus"
        :colors="avatarColors"
        class="avatar"
    />
    <h5 class="card-title">{{ authStore.current_user?.name }}</h5>
    <p class="email">{{ formatEmail(authStore.current_user?.email) }}</p>
  </div>
</template>

<script setup lang="ts">
import { useAuthStore } from "@/stores/auth.ts";
import Avatar from 'vue-boring-avatars';

const formatEmail = (email?: string) => {
  return email?.replace('@', '\u200B@');
};

const avatarColors = [
  '#264653', // Dark blue
  '#2a9d8f', // Teal
  '#e9c46a', // Yellow
  '#f4a261', // Orange
  '#e76f51'  // Coral
];

const authStore = useAuthStore();
</script>

<style scoped>
.card {
  max-width: 300px;
  margin: 12px 0;
  background: var(--vt-card);
  border: 1px solid var(--vt-border);
  border-radius: 12px;
  padding: 1.5rem;
  text-align: center;
  box-shadow: 0 2px 8px rgba(0, 0, 0, .25);
}
.avatar {
  border-radius: 50%;
}
.card-title {
  color: var(--vt-text);
  font-size: 15px;
  font-weight: 600;
  margin: 8px 0 4px;
}
.email {
  color: var(--vt-muted);
  font-size: 13px;
}
</style>
