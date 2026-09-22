/**
 * Bridge between the axios interceptor and the router.
 *
 * ApiClient cannot import the router directly: the router imports views, views import
 * stores, and stores import ApiClient — a cycle that breaks at module init. main.ts
 * registers the handler once the router exists instead.
 */
type SessionExpiredHandler = () => void;

/** A single expired token normally produces a burst of parallel 401s; collapse them. */
const DEDUP_WINDOW_MS = 1000;

let handler: SessionExpiredHandler | null = null;
let lastNotifiedAt = 0;

export const onSessionExpired = (fn: SessionExpiredHandler): void => {
    handler = fn;
};

/**
 * Report that the session is gone. Repeated calls inside the dedup window are ignored so a
 * tab firing several requests at once triggers one navigation, not one per request.
 */
export const notifySessionExpired = (): void => {
    if (!handler) return;

    const now = Date.now();
    if (now - lastNotifiedAt < DEDUP_WINDOW_MS) return;
    lastNotifiedAt = now;

    handler();
};
