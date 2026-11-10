# Code Guardian — web

A single-screen React UI for the scan service: enter a GitHub URL, press **Start**, watch the status
(polled every 2 s), and browse the critical vulnerabilities once the scan is `Finished`.

Vite 8 · React 19 · TypeScript 5.9 (strict, no `any`) · Vitest + Testing Library. No UI framework.

## Run against the backend

```bash
# 1. backend on :3000 (from the repo root)
npm run dev

# 2. UI on :5173 — /api and /graphql are proxied to http://localhost:3000
cd web && npm install && npm run dev
```

- Point the dev proxy elsewhere with `BACKEND_URL=http://host:port npm run dev`.
- Call an API on another origin directly (no proxy) with `VITE_API_BASE=https://scanner.example.com`
  at build time; it defaults to same-origin.
- Docker: `docker build -t code-guardian-web web/` builds the SPA and serves it from nginx, which
  proxies `/api/` and `/graphql` to `http://app:3000` (the backend's compose service name).

| Script | |
| --- | --- |
| `npm run dev` / `build` / `preview` | Vite dev server / type-check + production build / serve `dist/` |
| `npm run typecheck` | `tsc -b` over app, tests and config |
| `npm run lint` | ESLint (`strictTypeChecked` + react-hooks), zero warnings |
| `npm test` / `test:coverage` | Vitest (jsdom); coverage thresholds are 90 % |

## How it is built

```
src/
  api/          transport layer — the only code that knows wire formats
    types.ts      normalized model: ScanView (discriminated on status), VulnerabilityPage, ScanApi
    guards.ts     hand-written readers that narrow `unknown` JSON (no casts of response.json())
    rest.ts       RestScanApi   — POST /api/scan, GET /api/scan/:id?limit=100&cursor=…
    graphql.ts    GraphqlScanApi — startScan mutation, scan(id){ criticalVulnerabilities(first, after) }
    http.ts       fetch wrapper + REST error envelope → ApiError
    errors.ts     ApiError (code, status, details, `transient`)
  hooks/
    useScanPolling.ts        poll now, then every POLL_INTERVAL_MS until Finished/Failed
    useVulnerabilityPages.ts "Load more" pagination over a finished scan
  components/   ScanForm, TransportToggle, StatusBadge, ScanResults
  App.tsx       wiring + `?scan=<id>` URL state (refresh resumes polling)
```

- **One interface, two transports.** The REST | GraphQL toggle swaps the `ScanApi` implementation;
  both return the same `ScanView`, so nothing above `api/` branches on transport.
- **Always paginated.** Without `limit` the REST endpoint streams the complete vulnerability list,
  so the client always sends `limit=100` and follows `nextCursor`. GraphQL returns a bare list; a full
  page (`first` items) means "maybe more", continued `after` the last item's cursor.
- **Polling.** The next request is scheduled only after the previous one settles (no overlap); an
  `AbortController` cancels the in-flight request on unmount, scan change, or transport switch.
  Transient failures (network, 5xx, `RATE_LIMITED`, `NOT_READY`) keep polling behind a
  "reconnecting…" hint; anything else (e.g. `NOT_FOUND`) stops and is shown.
- **Accessibility.** Labelled input with `aria-invalid`/`aria-describedby` errors, status in a
  `role="status"` live region, native radio group for the transport, captioned table.

## Tests

Co-located `*.test.ts(x)` files; shared builders and a `fakeApi()` double live in `src/test/`.

- `api/rest.test.ts`, `api/graphql.test.ts` — wire mapping for every status, pagination parameters,
  error envelopes, malformed responses, aborts (global `fetch` stubbed).
- `hooks/*.test.tsx` — polling cadence, stop conditions, no-overlap, transient vs fatal errors,
  abort on unmount / id change (fake timers).
- `components/components.test.tsx` — form validation, status labels, results table, empty state, load more.
- `App.test.tsx` — end-to-end flows through the UI with an injected fake `ScanApi`.
