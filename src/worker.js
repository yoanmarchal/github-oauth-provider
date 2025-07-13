import { Hono } from 'hono';

const GITHUB_AUTH_URL = 'https://github.com/login/oauth/authorize';
const GITHUB_TOKEN_URL = 'https://github.com/login/oauth/access_token';

// instance Hono
const app = new Hono();

app.use(async (c, next) => {
  const { ORIGINS } = c.env;
  if (!ORIGINS) {
    console.error('ORIGINS environment variable is not set');
    return c.json({ message: 'ORIGINS environment variable is not set' }, 500);
  }
  const origins = ORIGINS.split(',').map(origin => origin.trim());

  c.res.headers.set('Access-Control-Allow-Origin', origins[0]);
  c.res.headers.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  c.res.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  await next();
});

// Route pour démarrer le flux OAuth
app.get('/auth/github', (c) => {
  const { OAUTH_CLIENT_ID, REDIRECT_URL } = c.env;
  const params = new URLSearchParams({
    client_id: OAUTH_CLIENT_ID,
    redirect_uri: REDIRECT_URL,
    scope: 'repo',
    response_type: 'code',
  });

  return c.redirect(`${GITHUB_AUTH_URL}?${params.toString()}`);
});

// Route pour gérer le callback OAuth de GitHub
app.get('/callback', async (c) => {
  const { code } = c.req.query();
  const { OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET, REDIRECT_URL } = c.env;

  if (!code) {
    return c.json({ message: 'Code is missing' }, 400);
  }

  try {
    // Échange du code d'autorisation contre un jeton d'accès
    const tokenResponse = await fetch(GITHUB_TOKEN_URL, {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
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
      throw new Error('Access token is missing in GitHub response');
    }

    // Utilisation du jeton d'accès pour obtenir les informations de l'utilisateur
    const userResponse = await fetch('https://api.github.com/user', {
      headers: {
        Authorization: `token ${tokenData.access_token}`,
        'User-Agent': 'cloudflare-worker-github-oauth',
      },
    });
    
    const userData = await userResponse.json();

    // Renvoyer les données de l'utilisateur et le jeton d'accès
    const responseData = {
      ...userData,
      access_token: tokenData.access_token,
    };
    
    return c.json(responseData);
    
  } catch (error) {
    console.error('Error during OAuth flow:', error.message);
    return c.json({ message: 'Authentication failed', error: error.message }, 500);
  }
});

// Exporter l'application pour qu'elle soit exécutée par le Worker Cloudflare
export default app;