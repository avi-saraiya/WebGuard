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
`extension/dist`. The backend must be running at `VITE_API_BASE_URL` (default `http://localhost:8000`).

- `src/background/`: service worker; owns scanning and the per-tab result cache (`chrome.storage.session`)
- `src/popup/`: React popup
- `src/services/`: backend client, popup↔worker messaging, URL helpers
- `src/types/`: TypeScript mirror of the backend API schemas
