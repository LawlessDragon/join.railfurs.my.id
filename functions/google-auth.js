// functions/google-auth.js
// Memulai alur Google OAuth — redirect ke halaman izin Google

export async function onRequest({ env }) {
  const clientId = env.GOOGLE_CLIENT_ID;
  const baseUrl  = env.BASE_URL;

  if (!clientId || !baseUrl) {
    return new Response('Server misconfigured', { status: 500 });
  }

  const params = new URLSearchParams({
    client_id:     clientId,
    redirect_uri:  `${baseUrl}/google-callback`,
    response_type: 'code',
    scope:         'openid profile',
    prompt:        'select_account',
  });

  return Response.redirect(
    `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`,
    302
  );
}
