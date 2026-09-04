# docs-site

The documentation site for Better Auth for Python (the `better-auth-server`
and `better-auth-client` packages), built with [VitePress](https://vitepress.dev).

```bash
npm ci
npm run docs:dev       # http://localhost:5173
npm run docs:build     # dead links and broken anchors fail the build
npm run docs:preview   # serve .vitepress/dist
```

`docs:build` runs VitePress, then `scripts/check-anchors.mjs` (validates every
internal anchor) and `scripts/build-llms.mjs` (writes `/llms.txt` and
`/llms-full.txt` from the sidebar, so a page missing from the sidebar fails
the build).

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
scripts/
  check-anchors.mjs   internal anchor validation
  build-llms.mjs      llms.txt and llms-full.txt generation
index.md              home
guide/                getting-started · concepts · configuration · client · agents
plugins/              index plus one page per plugin (26)
providers/            index plus one page per social provider (35)
migrate/from-node.md  migrating a TypeScript better-auth app
deploy/production.md  production checklist
```

Every code sample mirrors the real API in `src/better_auth/` and was executed
against the package before shipping. When the library changes, the snippets
change with it. That is why the site lives in this repository.
