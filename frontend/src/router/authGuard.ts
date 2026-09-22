import type { RouteLocationNormalized, RouteLocationRaw } from 'vue-router';
import { useAuthStore } from '@/stores/auth';
import { useSetupStore } from '@/stores/setup';

/**
 * Auth is enforced globally instead of with `beforeEnter` on the `/` record: `beforeEnter`
 * only runs when the parent record is entered from outside, so moving between child tabs
 * (/overview -> /users -> /ca) skipped the check entirely and an expired session was only
 * noticed by API calls failing.
 */
export const authGuard = async (to: RouteLocationNormalized): Promise<true | RouteLocationRaw> => {
    const authStore = useAuthStore();
    const setupStore = useSetupStore();

    try {
        if (!setupStore.isSetup) {
            return to.name === 'FirstSetup' ? true : { name: 'FirstSetup' };
        }

        if (to.query.oidc === 'success') {
            await authStore.finishOIDC();
        }

        if (to.meta.public) {
            // Already signed in and heading to the login page: send them into the app.
            if (to.name === 'Login' && authStore.isAuthenticated) {
                return { name: 'Overview' };
            }
            return true;
        }

        // Optimistic: trust in-memory state, and re-probe the server only when we have no
        // session on record (fresh page load, or a 401 just cleared it). An expiry that
        // happens while the page is open is caught by the 401 interceptor.
        if (authStore.isAuthenticated || (await authStore.verifySession())) {
            return true;
        }

        return { name: 'Login', query: { redirect: to.fullPath } };
    } catch (error) {
        console.error('Error checking setup or auth:', error);
        return { name: 'Login', query: { redirect: to.fullPath } };
    }
};
