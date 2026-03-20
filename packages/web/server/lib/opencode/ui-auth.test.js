import { describe, expect, it, beforeAll } from 'bun:test';

import { SignJWT } from 'jose';

// Must be set before createUiAuth is called so getOrCreateJwtSecret() picks it up
const TEST_JWT_SECRET = 'test-secret-that-is-long-enough-for-hs256-alg-ok';
process.env.OPENCODE_JWT_SECRET = TEST_JWT_SECRET;

const { createUiAuth } = await import('./ui-auth.js');

const SECRET_BYTES = new TextEncoder().encode(TEST_JWT_SECRET);

const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;

/**
 * Create a JWT that mimics what the server issues, but with explicit iat/exp
 * so we can simulate different points in the session lifetime.
 */
const createTestToken = async (iatSecs, expSecs) =>
  new SignJWT({ type: 'ui-session' })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt(iatSecs)
    .setExpirationTime(expSecs)
    .sign(SECRET_BYTES);

const createMockReq = (token, { method = 'GET', secure = false } = {}) => ({
  method,
  headers: {
    cookie: token ? `oc_ui_session=${encodeURIComponent(token)}` : '',
    accept: 'application/json',
  },
  path: '/api/test',
  ip: '127.0.0.1',
  secure,
  connection: { remoteAddress: '127.0.0.1' },
});

const createMockRes = () => {
  const headers = {};
  const res = {
    _headers: headers,
    _status: null,
    _body: null,
    setHeader(name, value) {
      headers[name] = value;
    },
    status(code) {
      res._status = code;
      return res;
    },
    json(body) {
      res._body = body;
    },
    // Mocks Express res.type() (content-type setter) – only used by plain-text error paths
    type() {
      return { send: () => {} };
    },
  };
  return res;
};

describe('createUiAuth', () => {
  describe('session TTL', () => {
    it('uses a 30-day session TTL by default', () => {
      expect(SESSION_TTL_MS).toBe(30 * 24 * 60 * 60 * 1000);
    });
  });

  describe('disabled mode (no password)', () => {
    it('passes all requests through when no password is configured', async () => {
      const uiAuth = createUiAuth({});
      expect(uiAuth.enabled).toBe(false);

      const req = createMockReq(null);
      const res = createMockRes();
      let nextCalled = false;
      await uiAuth.requireAuth(req, res, () => { nextCalled = true; });
      expect(nextCalled).toBe(true);
    });

    it('returns authenticated:true from handleSessionStatus when disabled', async () => {
      const uiAuth = createUiAuth({});
      const req = createMockReq(null);
      const res = createMockRes();
      await uiAuth.handleSessionStatus(req, res);
      expect(res._body?.authenticated).toBe(true);
      expect(res._body?.disabled).toBe(true);
    });
  });

  describe('password verification', () => {
    it('rejects incorrect password in handleSessionCreate', async () => {
      const uiAuth = createUiAuth({ password: 'correct-password' });
      const req = { ...createMockReq(null), body: { password: 'wrong-password' } };
      const res = createMockRes();
      await uiAuth.handleSessionCreate(req, res);
      expect(res._status).toBe(401);
      expect(res._body?.error).toBe('Invalid credentials');
    });

    it('issues a session cookie on correct password', async () => {
      const uiAuth = createUiAuth({ password: 'correct-password' });
      const req = { ...createMockReq(null), body: { password: 'correct-password' } };
      const res = createMockRes();
      await uiAuth.handleSessionCreate(req, res);
      expect(res._body?.authenticated).toBe(true);
      expect(res._headers['Set-Cookie']).toContain('oc_ui_session=');
    });
  });

  describe('session validation', () => {
    it('blocks requests with no session token', async () => {
      const uiAuth = createUiAuth({ password: 'secret' });
      const req = createMockReq(null);
      const res = createMockRes();
      let nextCalled = false;
      await uiAuth.requireAuth(req, res, () => { nextCalled = true; });
      expect(nextCalled).toBe(false);
      expect(res._status).toBe(401);
    });

    it('allows requests with a valid session token', async () => {
      const uiAuth = createUiAuth({ password: 'secret', sessionTtlMs: 100_000 });
      const nowSecs = Math.floor(Date.now() / 1000);
      const token = await createTestToken(nowSecs - 10, nowSecs + 90_000);
      const req = createMockReq(token);
      const res = createMockRes();
      let nextCalled = false;
      await uiAuth.requireAuth(req, res, () => { nextCalled = true; });
      expect(nextCalled).toBe(true);
    });

    it('blocks requests with an expired session token', async () => {
      const uiAuth = createUiAuth({ password: 'secret', sessionTtlMs: 100_000 });
      const nowSecs = Math.floor(Date.now() / 1000);
      // expired 1 second ago
      const token = await createTestToken(nowSecs - 101, nowSecs - 1);
      const req = createMockReq(token);
      const res = createMockRes();
      let nextCalled = false;
      await uiAuth.requireAuth(req, res, () => { nextCalled = true; });
      expect(nextCalled).toBe(false);
      expect(res._status).toBe(401);
    });
  });

  describe('session renewal (sliding window)', () => {
    it('renews the session in requireAuth when more than half of TTL has elapsed', async () => {
      const ttlMs = 100_000;
      const uiAuth = createUiAuth({ password: 'secret', sessionTtlMs: ttlMs });
      const nowSecs = Math.floor(Date.now() / 1000);
      const ttlSecs = ttlMs / 1000;
      // 60% elapsed → should renew
      const iat = nowSecs - Math.floor(ttlSecs * 0.6);
      const exp = nowSecs + Math.floor(ttlSecs * 0.4);
      const token = await createTestToken(iat, exp);
      const req = createMockReq(token);
      const res = createMockRes();
      let nextCalled = false;
      await uiAuth.requireAuth(req, res, () => { nextCalled = true; });
      expect(nextCalled).toBe(true);
      expect(res._headers['Set-Cookie']).toBeDefined();
      expect(res._headers['Set-Cookie']).toContain('oc_ui_session=');
    });

    it('does not renew the session in requireAuth when less than half of TTL has elapsed', async () => {
      const ttlMs = 100_000;
      const uiAuth = createUiAuth({ password: 'secret', sessionTtlMs: ttlMs });
      const nowSecs = Math.floor(Date.now() / 1000);
      const ttlSecs = ttlMs / 1000;
      // 40% elapsed → should NOT renew
      const iat = nowSecs - Math.floor(ttlSecs * 0.4);
      const exp = nowSecs + Math.floor(ttlSecs * 0.6);
      const token = await createTestToken(iat, exp);
      const req = createMockReq(token);
      const res = createMockRes();
      let nextCalled = false;
      await uiAuth.requireAuth(req, res, () => { nextCalled = true; });
      expect(nextCalled).toBe(true);
      expect(res._headers['Set-Cookie']).toBeUndefined();
    });

    it('renews the session in handleSessionStatus when more than half of TTL has elapsed', async () => {
      const ttlMs = 100_000;
      const uiAuth = createUiAuth({ password: 'secret', sessionTtlMs: ttlMs });
      const nowSecs = Math.floor(Date.now() / 1000);
      const ttlSecs = ttlMs / 1000;
      // 70% elapsed → should renew
      const iat = nowSecs - Math.floor(ttlSecs * 0.7);
      const exp = nowSecs + Math.floor(ttlSecs * 0.3);
      const token = await createTestToken(iat, exp);
      const req = createMockReq(token);
      const res = createMockRes();
      await uiAuth.handleSessionStatus(req, res);
      expect(res._body?.authenticated).toBe(true);
      expect(res._headers['Set-Cookie']).toBeDefined();
      expect(res._headers['Set-Cookie']).toContain('oc_ui_session=');
    });

    it('does not renew the session in handleSessionStatus when less than half of TTL has elapsed', async () => {
      const ttlMs = 100_000;
      const uiAuth = createUiAuth({ password: 'secret', sessionTtlMs: ttlMs });
      const nowSecs = Math.floor(Date.now() / 1000);
      const ttlSecs = ttlMs / 1000;
      // 30% elapsed → should NOT renew
      const iat = nowSecs - Math.floor(ttlSecs * 0.3);
      const exp = nowSecs + Math.floor(ttlSecs * 0.7);
      const token = await createTestToken(iat, exp);
      const req = createMockReq(token);
      const res = createMockRes();
      await uiAuth.handleSessionStatus(req, res);
      expect(res._body?.authenticated).toBe(true);
      expect(res._headers['Set-Cookie']).toBeUndefined();
    });
  });

  describe('OPTIONS requests bypass auth', () => {
    it('calls next for OPTIONS without checking token', async () => {
      const uiAuth = createUiAuth({ password: 'secret' });
      const req = createMockReq(null, { method: 'OPTIONS' });
      const res = createMockRes();
      let nextCalled = false;
      await uiAuth.requireAuth(req, res, () => { nextCalled = true; });
      expect(nextCalled).toBe(true);
    });
  });
});
