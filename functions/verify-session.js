// functions/verify-session.js
// Verifikasi token sesi: cek signature HMAC dan expiry

const HEADERS = {
  'Content-Type': 'application/json',
  'Cache-Control': 'no-store',
};

function json(data) {
  return new Response(JSON.stringify(data), { status: 200, headers: HEADERS });
}

function fromB64url(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return atob(str);
}

export async function onRequest({ request, env }) {
  const url   = new URL(request.url);
  const token = url.searchParams.get('token');

  if (!token) return json({ valid: false, reason: 'no_token' });

  try {
    const dotIdx = token.lastIndexOf('.');
    if (dotIdx === -1) return json({ valid: false, reason: 'malformed' });

    const payload = token.substring(0, dotIdx);
    const sig     = token.substring(dotIdx + 1);

    // Import key
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(env.SESSION_SECRET),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );

    // Convert hex → Uint8Array (constant-time via subtle.verify)
    const sigBytes = new Uint8Array(
      sig.match(/.{2}/g).map(h => parseInt(h, 16))
    );

    const valid = await crypto.subtle.verify(
      'HMAC', key, sigBytes, encoder.encode(payload)
    );

    if (!valid) return json({ valid: false, reason: 'invalid_signature' });

    // Decode payload
    let decoded;
    try { decoded = fromB64url(payload); }
    catch { return json({ valid: false, reason: 'malformed_payload' }); }

    const parts = decoded.split('|');
    if (parts.length !== 3) return json({ valid: false, reason: 'malformed_payload' });

    const [, provider, expiryStr] = parts;
    const expiry = parseInt(expiryStr, 10);

    if (isNaN(expiry) || Date.now() > expiry) {
      return json({ valid: false, reason: 'expired' });
    }

    return json({ valid: true, remaining: expiry - Date.now(), provider });

  } catch (err) {
    console.error('verify-session error:', err);
    return json({ valid: false, reason: 'error' });
  }
}
