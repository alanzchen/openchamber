/**
 * Custom event dispatched when any `/api/*` fetch returns HTTP 401.
 * `SessionAuthGate` listens for this event to transition back to the
 * locked (login) state without requiring a full page reload.
 */
export const SESSION_EXPIRED_EVENT = 'oc:session-expired' as const;
