# github-oauth-provider

Serveur d'authentification GitHub (Cloudflare Worker) pour TryHeadless CMS. Il garde le
`client_secret` de l'OAuth App, que le CMS, servi au navigateur, ne peut pas détenir.

## Routes

| Route | Rôle |
|---|---|
| `GET /auth/github?state=…` | Redirige vers GitHub. Le `state` (aléatoire, émis par le CMS) est transmis à GitHub, qui le renvoie au CMS ; le CMS refuse un retour dont le `state` ne correspond pas. |
| `GET /callback?code=…` | Échange le code contre un jeton d'accès, renvoie le profil et `access_token`. |
| `POST /revoke` `{ "token": "…" }` | Révoque le jeton auprès de GitHub (appelé à la déconnexion). |

Seules les origines listées dans `ORIGINS` reçoivent les en-têtes CORS.

## Configuration

Variables (`wrangler.toml` ou tableau de bord Cloudflare) :

- `OAUTH_CLIENT_ID` : client ID de l'OAuth App GitHub
- `REDIRECT_URL` : URL `/callback` du CMS (ex. `https://admin.example.com/callback`)
- `ORIGINS` : origines du CMS autorisées, séparées par des virgules

Secret, à ne jamais mettre dans `wrangler.toml` :

```txt
npx wrangler secret put OAUTH_CLIENT_SECRET
```

## Développement et déploiement

```txt
npm install
npm run dev
npm run deploy
```

Déployer ce Worker **avant** une version du CMS qui envoie un `state` : un ancien Worker ne le
transmettrait pas à GitHub, et le CMS refuserait alors toutes les connexions. Ce Worker reste
compatible avec les anciennes versions du CMS (le `state` est facultatif ici, c'est le CMS qui
l'exige).
