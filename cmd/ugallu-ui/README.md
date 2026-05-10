# ugallu-ui

SvelteKit SPA backed by [`ugallu-bff`](../ugallu-bff). Read-only
SOC view for the security.ugallu.io CRD group.

## Stack

- **SvelteKit 2** + **TypeScript strict**
- **Tailwind CSS** + **ShadCN-Svelte** primitives (bits-ui under
  the hood, lucide-svelte for icons)
- **adapter-static**: the build is a plain static bundle that
  ships in the same Pod as the BFF, served by an
  `nginx-distroless` sidecar with `/api` proxied to the BFF on
  port 8080.

The SPA never talks to the apiserver directly; every API call goes
through the BFF cookie session.

## Develop

The dev experience assumes the BFF is running on localhost:8080.

```bash
# terminal 1: BFF
cd ../ugallu-bff
export OIDC_CLIENT_SECRET=...
export COOKIE_SECRET=$(openssl rand -hex 32)
go run . -oidc-issuer https://keycloak.lab/realms/ugallu \
         -external-url http://localhost:5173

# terminal 2: SPA
cd ../ugallu-ui
npm install
npm run dev   # vite on http://localhost:5173, /api -> :8080
```

The Vite dev server proxies `/api`, `/auth`, `/healthz`, and
`/readyz` to the BFF. Cookies stay same-origin so the OIDC + PKCE
flow works without CORS gymnastics.

## Build for production

```bash
npm run build       # output in build/
```

The chart's `nginx-distroless` container mounts the `build/`
directory at `/srv/www/ugallu-ui/`.

## Layout

```
src/
├── app.css                  Tailwind + design tokens (HSL)
├── app.html                 root document
├── app.d.ts                 SvelteKit ambient types
├── lib/
│   ├── api/
│   │   ├── client.ts        typed fetch wrapper (handles 401 + login)
│   │   └── types.ts         OpenAPI schemas mirrored as TS types
│   ├── components/
│   │   ├── sidebar.svelte
│   │   ├── topbar.svelte
│   │   ├── class-badge.svelte
│   │   └── severity-badge.svelte
│   └── utils.ts             cn() class-name combiner
└── routes/
    ├── +layout.ts           load /me; redirect on 401
    ├── +layout.svelte       sidebar + topbar shell
    ├── +page.svelte         dashboard
    └── events/
        ├── +page.ts         load /events with URL filters
        └── +page.svelte     list view with filter pills
```

## Adding ShadCN-Svelte components

`components.json` is preconfigured. From the directory:

```bash
npx shadcn-svelte@latest add button
npx shadcn-svelte@latest add table dialog select
```

Components vendor into `src/lib/components/ui/`.

## What this does NOT cover (yet)

- Run management views.
- Configurations + Honeypots views.
- SE detail page beyond the list link.
- Live tail / SSE (future).
- Write endpoints / ack flow (future).
