// functions/verify-turnstile.js
// Verifikasi token Cloudflare Turnstile di sisi server

const HEADERS = {
  'Content-Type': 'application/json',
  'Cache-Control': 'no-store',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: HEADERS });
}

export async function onRequest({ request, env }) {
  if (request.method !== 'POST') {
    return json({ success: false, reason: 'method_not_allowed' }, 405);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ success: false, reason: 'bad_json' }, 400);
  }

  const { cfToken } = body;
  if (!cfToken) return json({ success: false, reason: 'no_token' });

  try {
    const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        secret:   env.TURNSTILE_SECRET_KEY,
        response: cfToken,
      }),
    });

    const data = await res.json();
    return json({ success: data.success === true });

  } catch (err) {
    console.error('verify-turnstile error:', err);
    return json({ success: false, reason: 'server_error' });
  }
}
