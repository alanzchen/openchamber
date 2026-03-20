import { SESSION_EXPIRED_EVENT } from './authEvents';

let interceptorInstalled = false;

/**
 * Wraps `window.fetch` to detect session expiry.
 *
 * Any HTTP 401 response from a path under `/api/` dispatches a
 * `SESSION_EXPIRED_EVENT` CustomEvent on `window`. `SessionAuthGate`
 * listens for this event and transitions back to the login screen
 * without requiring a page reload.
 *
 * Safe to call multiple times — installs at most once.
 */
export const installFetchInterceptor = (): void => {
  if (typeof window === 'undefined' || interceptorInstalled) {
    return;
  }
  interceptorInstalled = true;

  const originalFetch = window.fetch.bind(window);

  window.fetch = async (
    input: Parameters<typeof fetch>[0],
    init?: Parameters<typeof fetch>[1],
  ): ReturnType<typeof fetch> => {
    const response = await originalFetch(input, init);

    if (response.status === 401) {
      let pathname = '';
      try {
        if (typeof input === 'string') {
          pathname = input.startsWith('http') ? new URL(input).pathname : input;
        } else if (input instanceof URL) {
          pathname = input.pathname;
        } else if (input instanceof Request) {
          pathname = new URL(input.url).pathname;
        }
      } catch {
        // Ignore malformed URLs — no event fired.
      }

      if (pathname.startsWith('/api/')) {
        window.dispatchEvent(new CustomEvent(SESSION_EXPIRED_EVENT));
      }
    }

    return response;
  };
};
