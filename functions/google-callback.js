// functions/google-callback.js
// Menerima code dari Google, tukar dengan token, buat sesi 2 menit

function toB64url(str) {
  return btoa(str)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

async function makeToken(userId, provider, secret) {
  const expiry  = Date.now() + 2 * 60 * 1000;
  const payload = toB64url(`${userId}|${provider}|${expiry}`);

  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sigBuffer = await crypto.subtle.sign('HMAC', key, encoder.encode(payload));
  const sig = Array.from(new Uint8Array(sigBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');

  return `${payload}.${sig}`;
}

export async function onRequest({ request, env }) {
  const base = env.BASE_URL;
  const url  = new URL(request.url);
  const code = url.searchParams.get('code');

  if (!code) {
    return Response.redirect(`${base}/?error=no_code`, 302);
  }

  try {
    // 1. Tukar code → access token
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id:     env.GOOGLE_CLIENT_ID,
        client_secret: env.GOOGLE_CLIENT_SECRET,
        grant_type:    'authorization_code',
        code,
        redirect_uri:  `${base}/google-callback`,
      }),
    });

    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) {
      return Response.redirect(`${base}/?error=token_failed`, 302);
    }

    // 2. Ambil info user
    const userRes = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    const user = await userRes.json();

    if (!user.id) {
      return Response.redirect(`${base}/?error=user_failed`, 302);
    }

    // 3. Buat sesi & redirect ke form
    const token = await makeToken(user.id, 'google', env.SESSION_SECRET);
    return Response.redirect(
      `${base}/form?t=${encodeURIComponent(token)}`,
      302
    );

  } catch (err) {
    console.error('google-callback error:', err);
    return Response.redirect(`${base}/?error=server_error`, 302);
  }
}
