import { Hono } from 'hono';
import { cors } from 'hono/cors';

const GITHUB_AUTH_URL = 'https://github.com/login/oauth/authorize';
const GITHUB_TOKEN_URL = 'https://github.com/login/oauth/access_token';
const USER_AGENT = 'cloudflare-worker-github-oauth';

// Valeur aléatoire générée par le CMS : transmise telle quelle à GitHub, qui la renvoie au CMS.
const STATE_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;

const app = new Hono();

const allowedOrigins = (env) =>
  (env.ORIGINS ?? '')
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);

app.use(async (c, next) => {
  if (allowedOrigins(c.env).length === 0) {
    console.error('ORIGINS environment variable is not set');
    return c.json({ message: 'Server misconfigured' }, 500);
  }
  await next();
});

// Seules les origines listées dans ORIGINS reçoivent un en-tête CORS (et non toujours la première).
app.use(
  '*',
  cors({
    origin: (origin, c) => (allowedOrigins(c.env).includes(origin) ? origin : null),
    allowMethods: ['GET', 'POST', 'OPTIONS'],
    allowHeaders: ['Content-Type'],
    maxAge: 600,
  }),
);

// Démarre le flux OAuth. Le `state` du CMS protège contre la connexion forcée (login CSRF) :
// le CMS refuse un retour dont le `state` ne correspond pas à celui qu'il a émis.
app.get('/auth/github', (c) => {
  const { OAUTH_CLIENT_ID, REDIRECT_URL } = c.env;
  const { state } = c.req.query();

  if (state !== undefined && !STATE_PATTERN.test(state)) {
    return c.json({ message: 'Invalid state' }, 400);
  }

  const params = new URLSearchParams({
    client_id: OAUTH_CLIENT_ID,
    redirect_uri: REDIRECT_URL,
    scope: 'repo',
    response_type: 'code',
  });
  if (state) params.set('state', state);

  return c.redirect(`${GITHUB_AUTH_URL}?${params.toString()}`);
});

// Échange le code d'autorisation contre un jeton d'accès.
app.get('/callback', async (c) => {
  const { code } = c.req.query();
  const { OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET, REDIRECT_URL } = c.env;

  if (!code) {
    return c.json({ message: 'Code is missing' }, 400);
  }

  try {
    const tokenResponse = await fetch(GITHUB_TOKEN_URL, {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        client_id: OAUTH_CLIENT_ID,
        client_secret: OAUTH_CLIENT_SECRET,
        redirect_uri: REDIRECT_URL,
        code,
      }),
    });

    const tokenData = await tokenResponse.json();

    if (!tokenData.access_token) {
      // GitHub répond 200 avec un champ `error` (code expiré, déjà utilisé…).
      console.error('GitHub token exchange failed:', tokenData.error);
      return c.json({ message: 'Authentication failed' }, 401);
    }

    const userResponse = await fetch('https://api.github.com/user', {
      headers: {
        Authorization: `token ${tokenData.access_token}`,
        'User-Agent': USER_AGENT,
      },
    });

    const userData = await userResponse.json();

    return c.json({
      ...userData,
      access_token: tokenData.access_token,
    });
  } catch (error) {
    // Le détail reste dans les logs du Worker, pas dans la réponse.
    console.error('Error during OAuth flow:', error.message);
    return c.json({ message: 'Authentication failed' }, 500);
  }
});

// Révoque un jeton à la déconnexion : sans cela, un jeton copié reste valable indéfiniment.
// L'API de GitHub exige le client_secret, d'où ce passage par le Worker.
app.post('/revoke', async (c) => {
  const { OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET } = c.env;

  let token;
  try {
    ({ token } = await c.req.json());
  } catch {
    return c.json({ message: 'Invalid body' }, 400);
  }
  if (typeof token !== 'string' || token.length === 0 || token.length > 255) {
    return c.json({ message: 'Token is missing' }, 400);
  }

  const response = await fetch(`https://api.github.com/applications/${OAUTH_CLIENT_ID}/token`, {
    method: 'DELETE',
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: `Basic ${btoa(`${OAUTH_CLIENT_ID}:${OAUTH_CLIENT_SECRET}`)}`,
      'Content-Type': 'application/json',
      'User-Agent': USER_AGENT,
    },
    body: JSON.stringify({ access_token: token }),
  });

  // 204 : révoqué ; 404 : jeton déjà invalide. Dans les deux cas, il n'est plus utilisable.
  if (response.status === 204 || response.status === 404) {
    return c.body(null, 204);
  }
  console.error('GitHub token revocation failed:', response.status);
  return c.json({ message: 'Revocation failed' }, 502);
});

export default app;
