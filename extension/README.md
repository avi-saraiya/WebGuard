# WebGuard Extension

Chrome Manifest V3 extension (TypeScript + React 19, built with Vite).

```bash
npm ci
npm run build        # typecheck + production build into dist/
npm run dev          # rebuild dist/ on change
npm test             # Vitest unit/component tests
npm run lint         # ESLint + Prettier check
```

Load it in Chrome: open `chrome://extensions`, enable **Developer mode**, click **Load unpacked**, and pick
`extension/dist`. The backend must be running at `VITE_API_BASE_URL` (default `http://localhost:8000`). To try
pages with known findings, run `python3 ../tools/fixture-site/serve.py --https` from this directory.

| Path              | Contents                                                                                                 |
| ----------------- | -------------------------------------------------------------------------------------------------------- |
| `src/background/` | Service worker: scan orchestration, sender validation, per-tab result cache (`chrome.storage.session`)   |
| `src/collector/`  | `collectPageSignals`, injected into the page. **Must stay self-contained** (see the comment in the file) |
| `src/popup/`      | React popup (`App.tsx`) plus the results and finding-detail pages                                        |
| `src/components/` | Reusable UI pieces: severity summary and badges, finding cards, checks list, evidence view               |
| `src/services/`   | Backend client, popup ↔ worker messaging, URL helpers                                                    |
| `src/types/`      | TypeScript mirror of the backend API schemas                                                             |
| `src/test/`       | Vitest setup with an in-memory `chrome` mock, and shared fixtures                                        |

Permissions and data handling are documented in [`docs/security.md`](../docs/security.md).
