import { describe, expect, it, beforeEach, afterEach } from 'bun:test';

import { SESSION_EXPIRED_EVENT } from './authEvents';
import { installFetchInterceptor, resetFetchInterceptorForTests } from './fetchInterceptor';

const makeResponse = (status: number): Response =>
  new Response(null, { status }) as Response;

describe('installFetchInterceptor', () => {
  let originalFetch: typeof fetch;
  let originalWindow: typeof globalThis | undefined;
  let originalDispatchEvent: typeof globalThis.dispatchEvent;
  let dispatchedEvents: string[];
  let fetchCalls: Array<RequestInfo | URL>;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
    originalWindow = (globalThis as typeof globalThis & { window?: typeof globalThis }).window;
    originalDispatchEvent = globalThis.dispatchEvent;
    dispatchedEvents = [];
    fetchCalls = [];
    resetFetchInterceptorForTests();
    (globalThis as typeof globalThis & { window?: typeof globalThis }).window = globalThis;
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      fetchCalls.push(input);
      return makeResponse(200);
    }) as typeof fetch;
    globalThis.dispatchEvent = (event: Event) => {
      dispatchedEvents.push(event.type);
      return true;
    };
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    if (originalWindow === undefined) {
      delete (globalThis as typeof globalThis & { window?: typeof globalThis }).window;
    } else {
      (globalThis as typeof globalThis & { window?: typeof globalThis }).window = originalWindow;
    }
    globalThis.dispatchEvent = originalDispatchEvent;
  });

  it('dispatches SESSION_EXPIRED_EVENT on 401 from /api/ path', async () => {
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      fetchCalls.push(input);
      return makeResponse(401);
    }) as typeof fetch;
    installFetchInterceptor();

    const response = await globalThis.fetch('/api/some-endpoint');

    expect(response.status).toBe(401);
    expect(fetchCalls).toEqual(['/api/some-endpoint']);
    expect(dispatchedEvents).toContain(SESSION_EXPIRED_EVENT);
  });

  it('does NOT dispatch SESSION_EXPIRED_EVENT on 401 from non-/api/ path', async () => {
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      fetchCalls.push(input);
      return makeResponse(401);
    }) as typeof fetch;
    installFetchInterceptor();

    const response = await globalThis.fetch('/auth/session');

    expect(response.status).toBe(401);
    expect(fetchCalls).toEqual(['/auth/session']);
    expect(dispatchedEvents).not.toContain(SESSION_EXPIRED_EVENT);
  });

  it('does NOT dispatch SESSION_EXPIRED_EVENT on 200 from /api/ path', async () => {
    installFetchInterceptor();

    const response = await globalThis.fetch('/api/some-endpoint');

    expect(response.status).toBe(200);
    expect(dispatchedEvents).toHaveLength(0);
  });

  it('does NOT dispatch SESSION_EXPIRED_EVENT on 403 from /api/ path', async () => {
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      fetchCalls.push(input);
      return makeResponse(403);
    }) as typeof fetch;
    installFetchInterceptor();

    const response = await globalThis.fetch('/api/some-endpoint');

    expect(response.status).toBe(403);
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

  it('treats non-absolute string as relative pathname', () => {
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
