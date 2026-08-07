# Agentwall README and Brand Design

**Date:** 2026-08-07
**Status:** Approved for implementation on 2026-08-07

## Objective

Make the Agentwall GitHub front page look like a mature security product with broad developer adoption.
Create a professional logo system that works across the repository, product UI, release assets, and social previews.
Keep every claim precise and keep every install command usable today.

## Audience

1. A developer wants to understand the product and run it quickly.
2. A security operator wants evidence that the controls are real.
3. An enterprise reviewer wants clear boundaries, deployment facts, and assurance signals.
4. A contributor wants direct paths to architecture, documentation, security policy, and project governance.

## Product position

Agentwall is a runtime control and evidence product for AI agents.
It applies policy where an action becomes real, gives operators typed controls, and records verifiable evidence.
The front page presents Agentwall as a product first and a technical reference second.

The visual and written tone combines two qualities:

- **Sharp security product.** Precise language, clear proof, visible limits, and no inflated claims.
- **Enterprise platform.** Cohesive branding, strong product visuals, an assurance story, and clear deployment paths.

## Brand system

### Logo concept

Use the **protected center** as the core symbol.
An outer control frame surrounds an open inner boundary and a precise center point.
The symbol represents policy around an agent action without using a generic shield, padlock, robot, or letter monogram.

Refine the current concept into a professional geometric mark with these properties:

- The mark is readable at 16 pixels and remains distinct at display scale.
- The geometry uses one consistent corner radius and one optical stroke system.
- The protected center stays visible in monochrome.
- The shape avoids gradients, glow effects, bevels, and decorative shadows.
- The mark works on light and dark backgrounds.
- The wordmark uses a restrained enterprise sans-serif form.
- The wordmark does not depend on a local font to keep its intended shape.
- The system remains legible in GitHub light mode and dark mode.

### Logo deliverables

Replace the current public logo set with one consistent system:

1. `assets/brand/agentwall-logo-primary.svg` for the README and light backgrounds.
2. `assets/brand/agentwall-logo-reverse.svg` for dark backgrounds.
3. `assets/brand/agentwall-logo-mark.svg` for compact placements.
4. `assets/brand/agentwall-logo-monochrome.svg` for one-color use.
5. `public/assets/brand/agentwall-logo-primary.svg` for product light surfaces.
6. `public/assets/brand/agentwall-logo-mark.svg` for product navigation.
7. `public/assets/brand/agentwall-logo-monochrome.svg` for product one-color use.
8. `public/assets/brand/favicon.svg` for the local interface.
9. `public/assets/brand/agentwall-social-card.svg` as the editable social-card source.
10. `docs/assets/agentwall-social-preview.png` as the GitHub upload image.

The social preview PNG is 1280 by 640 pixels and smaller than 1 MiB.
The README uses a `<picture>` element with the primary logo for light mode and the reverse logo for dark mode.
The product UI, documentation, and social card use the same mark and proportions.
Obsolete public logo variants leave the repository after all references move.
Remove `.github/assets/logo.jpg` after the README and repository surfaces no longer reference it.

### Visual palette

Use graphite, cool white, and one mint signal color.
Use blue only for informational states inside the product interface.
The README does not use decorative color blocks or promotional gradients.

- Graphite: `#0F131B`
- Cool white: `#F1F5FA`
- Mint signal: `#5FE6C8`
- Steel border: `#313B49`
- Secondary text: `#A7B4C5`

## GitHub front-page structure

### 1. Product hero

Center the professional logo above a short product statement.
Use one sentence that states the outcome, not a feature list.
Add a compact badge row for CI, CodeQL, Node support, Apache-2.0, and the public security policy.

The hero includes two direct paths:

- **Run from source** links to the working quick-start section.
- **Read the architecture** links to `docs/architecture.md`.

Do not show a public npm install command until the public package exists.

### 2. Main interface visual

Place a fresh 16:9 screenshot of the current local operator console directly below the hero.
Capture the actual `main` application after the built-in incident simulation starts.
The simulation is an implemented product mode and labels every synthetic record as simulation data.

The hero screenshot must:

- show the product name, protection state, navigation, and a useful operator decision
- contain no secret, token, personal path, local username, or production host
- use the built-in `incident-chain-ransomware` simulation and the `sim-operator` identity
- remain readable at a GitHub content width
- use PNG without visible compression artifacts
- include accurate alternative text

Save the hero as `docs/assets/agentwall-console-hero.png`.

### 3. Detailed product visuals

Add two focused interface images later on the page:

1. `docs/assets/agentwall-approval-in-action.png` shows the simulated typed approval, risk, reason, and next action.
2. `docs/assets/agentwall-evidence-verification.png` shows simulated evidence beside the real audit verification controls.

Use screenshots from the real interface.
Do not use concept art or a design that the application does not implement.

Add `docs/assets/agentwall-readme-visuals.json` as the capture manifest.
Each image entry records the file, pixel dimensions, route, CSS selector, viewport, device scale, theme, source commit, seed request, required visible state, and alternative text.
The seed request is `POST /api/dashboard/control/simulation` with `{\"action\":\"start\"}`.
The source commit contains the logo assets and UI that the screenshot shows.

### 4. Product pillars

Present three concise pillars:

- **Enforce.** Apply network, tool, content, identity, MCP, and runtime policy.
- **Approve.** Route high-risk actions through typed operator decisions.
- **Prove.** Keep hash-chained records and independently verifiable evidence.

Each pillar links to a detailed guide.
Each pillar states one important boundary beside the capability.

### 5. Working quick start

Make source installation the primary path until npm publication completes.
Use this complete command block:

```bash
git clone https://github.com/repsecure/agentwall.git
cd agentwall
npm ci
npm run build
node dist/cli.js version
node dist/cli.js ui
```

Node.js 22.12 or newer is required.
`npm ci`, `npm run build`, and `node dist/cli.js version` must exit with status 0.
The version command prints the current package version.
The UI command stays active and prints its loopback URL.
After setup and service start, `node dist/cli.js doctor` exits 0 for clear, 1 for observed blocked traffic, or 2 when it cannot distinguish the state.

State the registry status plainly:

> The public npm package is not released yet. Use the source install below.

Remove the broken npm command from the README and user guide.
Correct the changelog sentence that says the package is already published.
Keep the intended package name `@repsecure/agentwall` clear without implying registry availability.

Package publication, npm organization changes, trusted publisher setup, release tags, and image publication remain separate approval-gated actions.

### 6. Capability matrix

Replace the long front-page feature catalog with a compact matrix.
Group features into policy, operator control, evidence, agent identity, MCP, and Linux host controls.
Link each row to the feature reference and its documented limits.

### 7. Architecture and assurance

Keep one readable Mermaid flow from agent action to policy, operator decision, audit chain, and external anchor.
Add a compact assurance block for:

- four verifier implementations
- the conformance corpus
- CodeQL and secret scanning
- package provenance and the release workflow
- documented security boundaries

Describe only controls that the repository and current workflows prove.

### 8. Limits and trust boundary

Keep the front page honest without leading with caveats.
Place a short trust-boundary section after the product and quick-start sections.
Link to `docs/limits.md` and the threat model.

Keep these limits visible:

- default proxy capture can be bypassed by a process that ignores proxy configuration
- TLS content stays opaque without reviewed interception
- audit verification proves integrity of written records, not completeness
- fleet state has per-instance scope

### 9. Documentation and project trust

End with a compact documentation map, the private security-report path, contribution links, governance, and the license.
Avoid a long list that repeats the feature reference.

## Repository metadata and social presentation

Keep the GitHub description short and product-focused.
Use repository topics that match implemented capabilities and current documentation.
Keep the project website field empty unless a maintained public product page exists.

Use `public/assets/brand/agentwall-social-card.svg` as the editable source.
Export `docs/assets/agentwall-social-preview.png` at 1280 by 640 pixels and below 1 MiB.
The card uses the professional mark, one product statement, and the graphite and mint palette.
Do not put badges, small interface text, or a feature list on the social card.

The implementation operator uploads the PNG through the approved GitHub repository settings workflow.
The operator verifies the live social preview on the public repository page.
Update the description and topics through the same approved workflow.
Do not fabricate adoption signals, customer logos, testimonials, download counts, or star counts.
The page earns a mature presentation through clarity, proof, and visual quality.

## Content rules

- Use Agentwall capitalization consistently.
- Use short active sentences.
- Use one term for one concept.
- Keep procedural sentences to one action.
- Keep detailed behavior in the existing guides.
- Do not use competitor names or links.
- Do not claim a public npm release before the public registry proves it.
- Do not call a workflow, dry run, or pending anchor a completed release or confirmed proof.
- Keep all commands and paths exact.
- Do not fabricate social proof or imply adoption that public evidence does not prove.

## Accessibility

- Give every image useful alternative text.
- Do not rely on color alone.
- Keep text inside screenshots large enough to read at GitHub width.
- Keep SVG title and description elements.
- Preserve contrast on light and dark backgrounds.
- Avoid badge-only explanations for critical state.

## Validation

| Check | Command or observation | Pass result |
| --- | --- | --- |
| Brand assets | `npm run check:brand` | Every SVG parses, contains `title` and `desc`, uses outlined wordmark paths, and meets its size and palette contract. |
| Contrast | `npm run check:brand` | Normal text reaches 4.5:1 and large text reaches 3:1 against its declared background. |
| Social preview | `npm run check:brand` | The PNG is 1280 by 640 pixels and smaller than 1 MiB. |
| README links | `npm run check:readme` | Every repository-relative image and document target exists. |
| Public copy | `npm run check:public-copy` | The command exits 0 with no competitor, placeholder, or punctuation finding. |
| Source install | Clean local clone, then run the quick-start commands | Install, build, and version exit 0. The UI prints a loopback URL. |
| npm state | `npm view @repsecure/agentwall version --json` | E404 is expected while the README states that the public package is not released. |
| Focused checks | `npm test -- tests/public-copy.test.ts tests/public-console.test.ts` | Both suites pass. |
| Complete checks | `npm run build && npm test` | The build and complete test suite exit 0. |
| Screenshot provenance | Read `docs/assets/agentwall-readme-visuals.json` and open each image | Every image matches its source commit, seed, selector, required state, dimensions, and alternative text. |
| README render | Open the live GitHub main page in light and dark themes at 1440 by 900 and 390 by 844 | Both logo variants, all images, headings, links, and code blocks render without clipping or contrast loss. |
| Public assurance | Inspect the live GitHub checks for the pushed commit | CI, CodeQL, secret scanning, and release provenance claims match live repository evidence. |

## Success criteria

- The first screen shows a professional Agentwall logo, a clear product outcome, trust badges, and the current interface.
- A reader understands Enforce, Approve, and Prove within one screen of the main visual.
- The logo works in primary, reverse, compact, monochrome, favicon, and social formats.
- Every public surface uses one consistent logo system.
- The interface screenshots show real implemented states and contain no sensitive data.
- The README provides one working installation path.
- The README does not show the unavailable npm command.
- The front page stays concise and moves detailed behavior to existing guides.
- The page states material security limits without weakening the product presentation.
- All repository links, images, copy checks, builds, and tests pass.
