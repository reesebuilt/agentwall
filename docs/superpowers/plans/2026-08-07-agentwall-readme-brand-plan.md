# Agentwall README and Brand Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a professional Agentwall logo system and a product-led GitHub front page with sharp, real interface visuals.

**Architecture:** Keep one geometric protected-center mark across repository and product surfaces. Present the README as a product decision page, move detail into existing guides, and prove visual claims with current UI screenshots and live repository checks.

**Tech Stack:** SVG, PNG, GitHub Markdown and HTML, Node.js 22.12+, browser capture, Agentwall built-in incident simulation

## Global Constraints

- Use Agentwall capitalization in public prose.
- Use graphite `#0F131B`, cool white `#F1F5FA`, mint `#5FE6C8`, steel `#313B49`, and secondary text `#A7B4C5`.
- Do not use a shield, padlock, robot, letter monogram, gradient, glow, bevel, or decorative shadow.
- Do not depend on a local font to render the wordmark.
- Do not claim public npm availability while `npm view @repsecure/agentwall version --json` returns E404.
- Do not fabricate stars, users, customers, testimonials, download counts, or customer logos.
- Use only current product states and mark every simulated state as simulation data.
- Do not put secrets, tokens, personal paths, usernames, production hosts, or real identities in images.
- Keep security limits beside the capability that each limit qualifies.
- Public repository or registry mutations need the approved operator workflow.

## File map

- `assets/brand/`: canonical source SVG logo system for documentation and repository surfaces.
- `public/assets/brand/`: product copies of the canonical mark, favicon, and social-card source.
- `docs/assets/`: README screenshots, social-preview PNG, and screenshot provenance manifest.
- `scripts/check-brand-assets.js`: deterministic SVG, palette, contrast, and PNG contract checks.
- `scripts/check-readme.js`: local README link, image, and theme-logo contract checks.
- `README.md`: short product-led GitHub front page.
- `docs/user-guide.md`, `docs/install.md`, `CHANGELOG.md`: truthful source-install and publication state.
- `package.json`: public presentation check commands.

---

### Task 1: Professional logo system

**Files:**
- Modify: `assets/brand/agentwall-logo-primary.svg`
- Create: `assets/brand/agentwall-logo-reverse.svg`
- Modify: `assets/brand/agentwall-logo-mark.svg`
- Modify: `assets/brand/agentwall-logo-monochrome.svg`
- Modify: `public/assets/brand/agentwall-logo-primary.svg`
- Create: `public/assets/brand/agentwall-logo-reverse.svg`
- Modify: `public/assets/brand/agentwall-logo-mark.svg`
- Modify: `public/assets/brand/agentwall-logo-monochrome.svg`
- Modify: `public/assets/brand/favicon.svg`
- Modify: `public/assets/brand/agentwall-social-card.svg`
- Create: `docs/assets/agentwall-social-preview.png`
- Create: `scripts/check-brand-assets.js`
- Modify: `package.json`
- Remove: `.github/assets/logo.jpg`

**Interfaces:**
- Consumes: the protected-center concept and the global palette.
- Produces: primary, reverse, mark, monochrome, favicon, social source, and 1280 by 640 PNG assets.
- Produces: `npm run check:brand`, which exits 0 only when every asset meets the declared contract.

- [ ] **Step 1: Add the failing brand contract check**

Create `scripts/check-brand-assets.js` with these checks:

- Parse every required SVG as XML.
- Require one non-empty `title` and `desc` in every SVG.
- Reject SVG `text`, gradients, filters, masks, external URLs, scripts, and embedded raster data.
- Require `viewBox` values of `0 0 960 256` for wordmarks and `0 0 512 512` for marks.
- Require the primary and reverse wordmarks to use path outlines.
- Require the canonical palette and reject undeclared colors.
- Require the PNG to be exactly 1280 by 640 pixels and smaller than 1,048,576 bytes.
- Compute WCAG contrast and require 4.5:1 for normal text and 3:1 for large text.

Add `"check:brand": "node scripts/check-brand-assets.js"` to `package.json`.

- [ ] **Step 2: Run the brand check and confirm the missing assets fail**

Run: `npm run check:brand`

Expected: nonzero exit that names the missing reverse logo and social-preview PNG.

- [ ] **Step 3: Draw the protected-center mark**

Use a 512 square viewBox.
Use one 448 square graphite field at `(32,32)` with a 104 radius.
Use one balanced mint octagonal control frame with a clear inner boundary.
Use one centered mint square as the protected action.
Keep 32 pixels of optical padding around the outer field.
Confirm the mark stays recognizable at 16, 28, 64, and 512 pixels.

- [ ] **Step 4: Build the primary and reverse wordmarks**

Use a 960 by 256 viewBox with the mark at the left and the outlined `Agentwall` wordmark at the right.
Use path outlines derived from the installed Montserrat variable font at a restrained semibold weight.
Use graphite wordmark fill for primary and cool-white fill for reverse.
Do not include a tagline in the primary or reverse logo.

- [ ] **Step 5: Build product and social assets**

Copy the canonical mark geometry into the public primary, reverse, mark, monochrome, and favicon files.
Build the social-card SVG at 1280 by 640 with a solid graphite background.
Use the line `Runtime control and verifiable evidence for AI agents.` as the only product statement.
Export `docs/assets/agentwall-social-preview.png` at 1280 by 640 and below 1 MiB.
Remove `.github/assets/logo.jpg` after no reference remains.

- [ ] **Step 6: Run brand validation**

Run: `npm run check:brand`

Expected: exit 0 and a summary for every required asset.

- [ ] **Step 7: Inspect the logo at operational sizes**

Open primary and reverse logos on light and dark backgrounds.
Open the mark at 16, 28, 64, and 512 pixels.
Confirm no clipped path, uneven frame, low-contrast wordmark, or ambiguous center remains.

- [ ] **Step 8: Commit the brand system**

```bash
git add assets/brand public/assets/brand docs/assets/agentwall-social-preview.png scripts/check-brand-assets.js package.json .github/assets/logo.jpg
git commit -m "brand: give Agentwall a professional identity"
```

---

### Task 2: Current product visuals

**Files:**
- Modify: `docs/assets/agentwall-console-hero.png`
- Modify: `docs/assets/agentwall-approval-in-action.png`
- Create: `docs/assets/agentwall-evidence-verification.png`
- Remove: `docs/assets/agentwall-console-full.png`
- Create: `docs/assets/agentwall-readme-visuals.json`

**Interfaces:**
- Consumes: the Task 1 product mark and the built-in `POST /api/dashboard/control/simulation` route.
- Produces: one 16:9 hero and two focused product images with complete provenance.

- [ ] **Step 1: Build and launch the current product**

Run: `npm run build`

Launch the built server with a temporary loopback-only configuration, a temporary audit path, and `AGENTWALL_ALLOW_LOOPBACK_DEV=1`.
Use port `32145` and keep the service process under the harness process manager.

- [ ] **Step 2: Start the implemented incident simulation**

Open `http://127.0.0.1:32145/` at a 1600 by 900 CSS viewport with device scale 1.5.
POST `{"action":"start"}` to `/api/dashboard/control/simulation` from the same origin.
Wait until the UI shows `sim-operator`, a critical pending approval, and the simulation disclaimer.

- [ ] **Step 3: Capture the hero**

Capture the viewport as `docs/assets/agentwall-console-hero.png`.
The image must show the branded navigation, product posture, useful event state, and a visible simulation label.

- [ ] **Step 4: Capture approval and evidence details**

Capture the `#approvals` element as `docs/assets/agentwall-approval-in-action.png`.
Capture the `#evidence` element as `docs/assets/agentwall-evidence-verification.png`.
Keep text at a readable size and keep action state labels inside each frame.

- [ ] **Step 5: Record screenshot provenance**

Create `docs/assets/agentwall-readme-visuals.json` as a JSON array.
Each entry contains `file`, `pixelWidth`, `pixelHeight`, `route`, `selector`, `viewport`, `deviceScaleFactor`, `theme`, `sourceCommit`, `seedRequest`, `requiredVisibleState`, and `alt`.
Use the Task 1 commit for `sourceCommit`.
Use `{"method":"POST","path":"/api/dashboard/control/simulation","body":{"action":"start"}}` for `seedRequest`.

- [ ] **Step 6: Inspect and sanitize every image**

Confirm each file matches its manifest dimensions.
Confirm each image contains no token, personal path, username, private host, IP address, or real identity.
Confirm every displayed record uses the built-in simulation labels.

- [ ] **Step 7: Commit the current product visuals**

```bash
git add docs/assets
git commit -m "docs: show the current Agentwall product"
```

---

### Task 3: Product-led GitHub front page

**Files:**
- Modify: `README.md`
- Modify: `docs/user-guide.md`
- Modify: `docs/install.md`
- Modify: `CHANGELOG.md`
- Create: `scripts/check-readme.js`
- Modify: `package.json`

**Interfaces:**
- Consumes: Task 1 logos and Task 2 screenshot manifest.
- Produces: a concise GitHub README and one truthful source-install path.
- Produces: `npm run check:readme`, which fails on a missing local target or incomplete light/dark logo markup.

- [ ] **Step 1: Add the failing README contract check**

Create `scripts/check-readme.js`.
Parse Markdown links, Markdown images, and HTML `href`, `src`, and `srcset` values from `README.md`.
Ignore absolute HTTP URLs and fragment-only links.
Resolve every repository-relative target and fail if its file is absent.
Require one `<picture>` with primary and reverse logo sources.
Require the three manifest image paths.
Add `"check:readme": "node scripts/check-readme.js README.md"` to `package.json`.

Run: `npm run check:readme`

Expected: nonzero exit because the current README lacks the new logo and product image contract.

- [ ] **Step 2: Replace the README information hierarchy**

Use this section order:

1. Theme-aware Agentwall logo, product statement, badges, and source and architecture links.
2. Current product hero image.
3. Enforce, Approve, and Prove product pillars.
4. Source quick start and plain npm publication status.
5. Compact capability and limit matrix.
6. Focused approval image and evidence image.
7. Mermaid architecture flow.
8. Assurance evidence and trust boundaries.
9. Compact documentation map, security process, contribution path, governance, and license.

Use `<picture>` with `assets/brand/agentwall-logo-reverse.svg` for dark mode and `assets/brand/agentwall-logo-primary.svg` for light mode.
Use the exact source commands from the approved specification.
Do not use `npm install -g @repsecure/agentwall`.

- [ ] **Step 3: Correct every false npm publication statement**

Replace the npm install block in `docs/user-guide.md` with the source build and launcher path.
Change `npm install` to `npm ci` in `docs/install.md`.
Change the changelog claim to state that `@repsecure/agentwall` is the intended scoped package name and is not public yet.
Keep registry publication as a separate approval-gated release action.

- [ ] **Step 4: Run presentation checks**

Run: `npm run check:brand && npm run check:readme && npm run check:public-copy`

Expected: all three commands exit 0.

- [ ] **Step 5: Render and inspect the README locally**

Render the GitHub-compatible Markdown.
Inspect at 1440 by 900 and 390 by 844 in light and dark themes.
Confirm the correct logo variant, sharp images, readable code, and no clipped table or Mermaid block.

- [ ] **Step 6: Commit the GitHub front page**

```bash
git add README.md docs/user-guide.md docs/install.md CHANGELOG.md scripts/check-readme.js package.json
git commit -m "docs: make the Agentwall front page product-led"
```

---

### Task 4: Verification and public repository presentation

**Files:**
- Verify: all Task 1 through Task 3 files
- Update through approved GitHub settings: repository description, topics, and social preview

**Interfaces:**
- Consumes: the complete repository presentation.
- Produces: a pushed `main` commit with passing local and GitHub checks and a live professional repository page.

- [ ] **Step 1: Run focused checks**

Run: `npm test -- tests/public-copy.test.ts tests/public-console.test.ts`

Expected: both suites pass.

- [ ] **Step 2: Run the complete repository checks**

Run: `npm run build && npm test`

Expected: build exit 0 and all test suites pass.

- [ ] **Step 3: Prove the source installation path**

Clone the committed repository into a temporary directory.
Run `npm ci`, `npm run build`, and `node dist/cli.js version` inside that clone.
Expected: all three commands exit 0 and version prints the package version.

- [ ] **Step 4: Recheck public npm state**

Run: `npm view @repsecure/agentwall version --json`

Expected while unpublished: E404 and a README that clearly directs users to source installation.

- [ ] **Step 5: Push the commits**

```bash
git push origin main
```

- [ ] **Step 6: Wait for live GitHub checks**

Watch every workflow for the pushed `main` commit.
Require CI, CodeQL, Security, and Scorecard jobs to finish without a failing job.
Do not describe a skipped or absent check as passed.

- [ ] **Step 7: Update approved repository presentation settings**

Set the repository description to `Runtime control and verifiable evidence for AI agents.`
Use only topics that match implemented and documented capabilities.
Upload `docs/assets/agentwall-social-preview.png` as the repository social preview.
Do not set a website URL unless a maintained product page exists.

- [ ] **Step 8: Inspect the live public page**

Open the public repository main page in light and dark themes at 1440 by 900 and 390 by 844.
Confirm the logo, social preview, product images, badges, relative links, code blocks, and Mermaid flow render correctly.

- [ ] **Step 9: Confirm the final repository state**

Run: `git status --short --branch`

Expected: `main` matches `origin/main` with zero staged, unstaged, or untracked files.
