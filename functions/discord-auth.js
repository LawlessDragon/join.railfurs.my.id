// functions/discord-auth.js
// Memulai alur Discord OAuth — redirect ke halaman izin Discord

export async function onRequest({ env }) {
  const clientId = env.DISCORD_CLIENT_ID;
  const baseUrl  = env.BASE_URL;

  if (!clientId || !baseUrl) {
    return new Response('Server misconfigured', { status: 500 });
  }

  const params = new URLSearchParams({
    client_id:     clientId,
    redirect_uri:  `${baseUrl}/discord-callback`,
    response_type: 'code',
    scope:         'identify',
    prompt:        'consent',
  });

  return Response.redirect(
    `https://discord.com/oauth2/authorize?${params.toString()}`,
    302
  );
}
