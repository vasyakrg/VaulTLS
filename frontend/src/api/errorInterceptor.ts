import axios from 'axios';
import { notifySessionExpired } from '@/api/sessionExpired.ts';

/**
 * Endpoints that are allowed to answer 401 without it meaning "the session just died":
 * the session probe, the login attempt itself, logging out, and the setup check. Callers
 * of these handle the failure themselves.
 */
const NO_REDIRECT_ON_401 = ['/auth/me', '/auth/login', '/auth/logout', '/server/setup'];

const isSessionProbe = (url?: string): boolean =>
    !!url && NO_REDIRECT_ON_401.some((path) => url.startsWith(path));

/**
 * Give every failed response a usable `data.error` and turn an unexpected 401 into a
 * session-expired signal.
 */
export const handleResponseError = (error: unknown): unknown => {
    if (!axios.isAxiosError(error) || !error.response) {
        return error;
    }

    // Callers read `err.response.data.error`. Guard rejections and proxy errors have no
    // such body, which used to surface as "Failed to fetch ...: undefined". Give them one.
    // Blob bodies are left alone — download() parses those itself.
    const data = error.response.data;
    const hasErrorField =
        typeof data === 'object' && data !== null && typeof (data as { error?: unknown }).error === 'string';
    if (!hasErrorField && !(typeof Blob !== 'undefined' && data instanceof Blob)) {
        error.response.data = {
            error: error.response.statusText || `HTTP ${error.response.status}`,
        };
    }

    if (error.response.status === 401 && !isSessionProbe(error.config?.url)) {
        notifySessionExpired();
    }

    return error;
};
