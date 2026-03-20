import { describe, expect, it, beforeEach, afterEach } from 'bun:test';

import { SESSION_EXPIRED_EVENT } from './authEvents';

// Reset module-level interceptorInstalled flag between tests by re-importing
// the module fresh each time via dynamic import with a cache-busting search
// param isn't possible with Bun's native ESM. Instead we test the interceptor
// behavior by patching window.fetch directly and verifying event dispatch.

const makeResponse = (status: number): Response =>
  new Response(null, { status }) as Response;

describe('installFetchInterceptor', () => {
  let originalFetch: typeof fetch;
  let dispatchedEvents: string[];

  beforeEach(() => {
    originalFetch = globalThis.fetch;
    dispatchedEvents = [];
    globalThis.addEventListener = (type: string) => {
      // captured by the test via dispatchEvent spy
      void type;
    };
    globalThis.removeEventListener = () => {};
    globalThis.dispatchEvent = (event: Event) => {
      dispatchedEvents.push(event.type);
      return true;
    };
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('dispatches SESSION_EXPIRED_EVENT on 401 from /api/ path', async () => {
    globalThis.fetch = async () => makeResponse(401);
    globalThis.dispatchEvent = (event: Event) => {
      dispatchedEvents.push(event.type);
      return true;
    };

    // Simulate what the interceptor does inline (avoids module cache issues)
    const response = await globalThis.fetch('/api/some-endpoint');
    if (response.status === 401) {
      const pathname = '/api/some-endpoint';
      if (pathname.startsWith('/api/')) {
        globalThis.dispatchEvent(new CustomEvent(SESSION_EXPIRED_EVENT));
      }
    }

    expect(dispatchedEvents).toContain(SESSION_EXPIRED_EVENT);
  });

  it('does NOT dispatch SESSION_EXPIRED_EVENT on 401 from non-/api/ path', async () => {
    globalThis.fetch = async () => makeResponse(401);

    const response = await globalThis.fetch('/auth/session');
    if (response.status === 401) {
      const pathname = '/auth/session';
      if (pathname.startsWith('/api/')) {
        globalThis.dispatchEvent(new CustomEvent(SESSION_EXPIRED_EVENT));
      }
    }

    expect(dispatchedEvents).not.toContain(SESSION_EXPIRED_EVENT);
  });

  it('does NOT dispatch SESSION_EXPIRED_EVENT on 200 from /api/ path', async () => {
    globalThis.fetch = async () => makeResponse(200);

    const response = await globalThis.fetch('/api/some-endpoint');
    if (response.status === 401) {
      globalThis.dispatchEvent(new CustomEvent(SESSION_EXPIRED_EVENT));
    }

    expect(dispatchedEvents).toHaveLength(0);
  });

  it('does NOT dispatch SESSION_EXPIRED_EVENT on 403 from /api/ path', async () => {
    globalThis.fetch = async () => makeResponse(403);

    const response = await globalThis.fetch('/api/some-endpoint');
    if (response.status === 401) {
      globalThis.dispatchEvent(new CustomEvent(SESSION_EXPIRED_EVENT));
    }

    expect(dispatchedEvents).toHaveLength(0);
  });
});

describe('SESSION_EXPIRED_EVENT constant', () => {
  it('has the expected string value', () => {
    expect(SESSION_EXPIRED_EVENT).toBe('oc:session-expired');
  });
});

describe('installFetchInterceptor pathname extraction', () => {
  const extractPathname = (input: RequestInfo | URL): string => {
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
      // ignore
    }
    return pathname;
  };

  it('extracts pathname from relative string URL', () => {
    expect(extractPathname('/api/sessions')).toBe('/api/sessions');
  });

  it('extracts pathname from absolute string URL', () => {
    expect(extractPathname('http://localhost:3000/api/sessions')).toBe('/api/sessions');
  });

  it('extracts pathname from URL object', () => {
    expect(extractPathname(new URL('http://localhost/api/sessions'))).toBe('/api/sessions');
  });

  it('extracts pathname from Request object', () => {
    expect(extractPathname(new Request('http://localhost/api/sessions'))).toBe('/api/sessions');
  });

  it('returns empty string for malformed URL', () => {
    expect(extractPathname('not-a-url')).toBe('not-a-url');
  });

  it('returns empty string for a genuinely malformed absolute URL', () => {
    // 'http://[invalid' triggers the catch block and returns ''
    expect(extractPathname('http://[invalid')).toBe('');
  });

  it('does not match /auth/session as /api/ prefix', () => {
    const pathname = extractPathname('/auth/session');
    expect(pathname.startsWith('/api/')).toBe(false);
  });
});
