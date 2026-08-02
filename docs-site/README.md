# docs-site

The documentation site for `better-auth-server`, built with
[VitePress](https://vitepress.dev).

```bash
npm ci
npm run docs:dev       # http://localhost:5173
npm run docs:build     # dead links fail the build
npm run docs:preview   # serve .vitepress/dist
```

## Deploying on Vercel

Import the repository and set **Root Directory** to `docs-site`. Everything
else is detected, but for the record:

| Setting | Value |
| --- | --- |
| Root directory | `docs-site` |
| Framework preset | VitePress |
| Build command | `npm run docs:build` |
| Output directory | `.vitepress/dist` |
| Install command | `npm ci` |

Vercel sets `VERCEL_PROJECT_PRODUCTION_URL` on its own, which the config reads
to emit `og:url` and a sitemap. Building anywhere else, set `SITE_URL` to the
public origin to get the same; without either, both are omitted rather than
guessed.

## Layout

```
.vitepress/
  config.mts          nav, sidebar, local search, head meta, favicon
  theme/
    index.ts          extends the default theme
    custom.css        the space theme (OKLCH tokens, both schemes)
    Starfield.vue     canvas starfield, scroll parallax, reduced-motion safe
index.md              home
guide/                getting-started · concepts · configuration
plugins/index.md      all 26 plugins
providers/index.md    all 35 social providers
migrate/from-node.md  migrating a TypeScript better-auth app
deploy/production.md  production checklist
```

Every code sample mirrors the real API in `src/better_auth/` and was executed
against the package before shipping. When the library changes, the snippets
change with it — that is why the site lives in this repository.
