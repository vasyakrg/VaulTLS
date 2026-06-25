import './assets/tailwind.css'
import './assets/theme.css'
import 'primeicons/primeicons.css'

import { createApp } from 'vue'
import { createPinia } from 'pinia'
import PrimeVue from 'primevue/config'
import ToastService from 'primevue/toastservice'
import router from './router/router'
import { i18n } from './plugins/i18n'
import { VaulTLSPreset } from './theme/preset'
import App from './App.vue'
import { useSetupStore } from '@/stores/setup.ts'
import { useAuthStore } from '@/stores/auth.ts'

async function initApp() {
  const pinia = createPinia()
  const app = createApp(App)
  app.use(pinia)
  app.use(i18n)
  app.use(PrimeVue, { theme: { preset: VaulTLSPreset, options: { darkModeSelector: '.dark' } } })
  app.use(ToastService)

  const setupStore = useSetupStore()
  await setupStore.init()
  const authStore = useAuthStore()
  await authStore.init()

  app.use(router)
  app.mount('#app')
}
initApp().catch((err) => console.error('Failed to initialize app:', err))
