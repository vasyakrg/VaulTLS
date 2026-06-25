import { ref } from 'vue'

const COOKIE = 'vaultls_sidebar'
function readCookie(): boolean {
  const m = document.cookie.match(new RegExp('(?:^|; )' + COOKIE + '=([^;]+)'))
  return m?.[1] === 'collapsed'
}
const collapsed = ref<boolean>(readCookie())

export function useSidebar() {
  const toggle = () => {
    collapsed.value = !collapsed.value
    document.cookie = `${COOKIE}=${collapsed.value ? 'collapsed' : 'expanded'}; path=/; max-age=31536000`
  }
  return { collapsed, toggle }
}
