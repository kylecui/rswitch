# rSwitch Module Marketplace

This directory contains a fully static documentation portal for browsing rSwitch modules.

## Files

- `index.html` - Single-page app shell and client-side rendering logic
- `style.css` - Local styles for layout, cards, badges, modal, and responsiveness
- `modules.json` - Module catalog consumed by `fetch()` at runtime

## Run Locally

From this directory (`docs/marketplace/`):

```bash
python3 -m http.server 8080
```

Then open:

- `http://localhost:8080/index.html`

Using an HTTP server is required because browsers block `fetch("./modules.json")` from local `file://` URLs.

## Updating `modules.json`

When new modules are added to rSwitch:

1. Add a new object to `modules.json` with required fields:
   - `name`, `version`, `abi_version`, `author`, `description`
   - `stage`, `hook`, `category`, `flags`, `license`, `required`
2. Include rich detail fields used by the details modal:
   - `full_description`, `dependencies`, `compatibility`, `usage_example`
3. Keep stage values aligned with the project stage assignment table.
4. Keep categories aligned with current UI tabs:
   - `L2 Switching`, `L3 Routing`, `Security`, `QoS`, `Monitoring`, `Tunneling`

Tip: keep entries sorted by stage for easy review.

## Deploying to GitHub Pages

Option A (project docs path):

1. Push this directory to your repository branch.
2. In repository settings, enable **Pages**.
3. Set source to the branch/folder that contains `docs/`.
4. Publish and open `/docs/marketplace/`.

Option B (dedicated docs branch):

1. Copy `docs/marketplace/` to the branch used for Pages.
2. Ensure `index.html`, `style.css`, and `modules.json` stay in the same folder.
3. Publish and verify `modules.json` loads without CORS or 404 errors.

## Future Plans

- User reviews and star ratings per module
- Download/use counters from release artifacts
- Module compatibility matrix by kernel/libbpf versions
- Signed module metadata and trust verification badges
