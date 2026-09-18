# BreachLabs Website — Product Requirements Document

**Version:** 1.0  
**Date:** 18 September 2026  
**Status:** Ready for implementation  
**Project:** BreachLabs  
**Repository:** notaayushsrivastava/BreachLabs  
**Website scope:** New, isolated implementation under `website/`

---

## 1. Product Summary

BreachLabs is an autonomous AI application-security engineer designed to assess software immediately after it is built.

The website should communicate that idea quickly and credibly: **Build. Break. Verify. Fix.**

The site is a polished product/technical landing page for the BreachLabs project. It should explain the problem, the security-assessment workflow, the architecture, capabilities, safety model, hackathon MVP, and project status without feeling like a generic cybersecurity template.

### Primary experience goal

A first-time visitor should understand within roughly 10 seconds:

1. What BreachLabs is.
2. Why it exists.
3. How its assessment loop works.
4. What makes the approach different.
5. Where to inspect the project or run the demo.

---

## 2. Non-Goals

The first website release will **not**:

- Modify or refactor existing BreachLabs application code.
- Replace the existing project architecture.
- Become a full security dashboard or authenticated SaaS product.
- Execute scans from the marketing site.
- Collect sensitive target/application data.
- Require a React/Next.js rewrite of the existing project.
- Add unnecessary animations, decorative 3D scenes, or stock cybersecurity imagery.

The implementation must live entirely inside the new `website/` directory.

---

## 3. Target Users

### A. Technical evaluator / judge

Wants to understand the technical novelty, architecture, safety controls, and demo story quickly.

**Needs:** concise architecture, evidence workflow, tooling, sandboxing, measurable outputs.

### B. Developer / security engineer

Wants to know how BreachLabs fits into a software development workflow.

**Needs:** build → discover → test → investigate → verify → fix → retest narrative.

### C. Hackathon visitor / general technical audience

Needs a simple explanation without having to understand every security acronym.

**Needs:** strong visual storytelling and plain-language copy.

### D. Potential contributor

Wants to understand project scope and where the project is headed.

**Needs:** repository CTA, roadmap/status, architecture, and project principles.

---

## 4. Product Positioning

### Core statement

> **Give every application its own security engineer.**

### Supporting statement

BreachLabs brings security validation into the software-building loop by combining an AI security investigator with controlled security tooling, deterministic scanners, browser automation, isolated execution, evidence collection, verification, and reporting.

### Brand personality

- Technical
- Precise
- Calm
- Modern
- Confident without hype
- Security-conscious
- Builder-oriented

Avoid:

- Fear-driven cybersecurity marketing
- Excessive hacker clichés
- “Military-grade” language
- Fake terminal walls
- Neon overload
- Generic padlock imagery
- Unsubstantiated claims such as “unhackable” or “100% secure”

---

## 5. Visual Direction

### Design principle

**Minimalism with technical depth.**

The visual system should feel closer to a premium developer tool / infrastructure product than a conventional cybersecurity landing page.

Use:

- Generous whitespace.
- Strong typographic hierarchy.
- Restrained borders.
- Subtle surface elevation.
- Monochrome or near-monochrome foundations with one restrained accent.
- Fine grid/technical details used sparingly.
- Small status indicators.
- Compact diagrams.
- Crisp cards.
- Subtle motion that communicates state or flow.

Do not use:

- Large gradients everywhere.
- Excessive glassmorphism.
- Heavy drop shadows.
- Oversized decorative illustrations.
- Constant particle animations.
- Animations that reduce readability.
- Excessively rounded “everything is a pill” UI.

### Reference implementation language

Use **shadcn/ui visual conventions** for component anatomy, spacing, tokens, borders, states, and accessibility.

Use **Magic UI-style motion patterns** selectively for:

- subtle entrance transitions,
- animated workflow indicators,
- border/beam treatments,
- hover feedback,
- lightweight background motion,
- progressive disclosure.

Because the requested stack is **HTML + TailwindCSS + Flask**, do not introduce React solely to consume shadcn/ui or Magic UI packages. Recreate the relevant component patterns in semantic HTML/Tailwind/vanilla JavaScript while preserving the design language and interaction intent.

---

## 6. Technology Requirements

### Backend

- Python
- Flask
- Jinja2 templates
- Static asset serving through Flask
- No changes to existing BreachLabs backend modules

### Frontend

- Semantic HTML5
- TailwindCSS
- Vanilla JavaScript where interaction is required
- CSS custom properties for design tokens
- Responsive layout
- Accessible keyboard/focus states

### Component language

Build reusable Jinja partials/components for:

- Header
- Buttons
- Badge/status chip
- Section heading
- Feature card
- Architecture node
- Workflow step
- Code/evidence panel
- Metric/stat card
- FAQ item
- Footer

### Optional tooling

A Tailwind build step may be used inside `website/`, provided it does not alter files outside that directory.

---

## 7. Information Architecture

The primary site should be a single-page experience with optional supporting routes.

### Required sections

1. Navigation
2. Hero
3. Core loop
4. Why BreachLabs
5. Capabilities
6. Architecture
7. Evidence / verification
8. Safety
9. Hackathon MVP / status
10. CTA
11. Footer

### Optional supporting routes

- `/architecture`
- `/demo`
- `/docs`

These should only be implemented if they provide real value; the MVP can remain one page.

---

## 8. Page Requirements

## 8.1 Navigation

### Content

- BreachLabs wordmark/name
- Product sections: Workflow, Architecture, Safety
- GitHub CTA
- Optional Demo CTA

### Behavior

- Sticky/fixed navigation after initial scroll.
- Transparent or low-contrast surface at top.
- Subtle border/background treatment on scroll.
- Mobile navigation collapses into an accessible menu.

### Design

Keep the header compact. It should establish the brand without consuming hero real estate.

---

## 8.2 Hero

### Primary headline

**Give every application its own security engineer.**

### Supporting copy

BreachLabs is an autonomous AI application-security engineer that helps validate software immediately after it is built — from discovery and deterministic scanning to investigation, verification, and evidence-backed reporting.

### Primary CTA

**View on GitHub**

### Secondary CTA

**See how it works**

### Supporting visual

Create a restrained “security assessment run” visualization rather than a generic illustration.

Example:

```
TARGET
  ↓
SANDBOX
  ↓
DISCOVER
  ↓
SCAN
  ↓
INVESTIGATE
  ↓
VERIFY
  ↓
REPORT
```

The visualization can have a subtle active-state animation.

### Hero requirements

- Above-the-fold clarity.
- No huge paragraph.
- Strong typographic contrast.
- Visual should support the product concept rather than compete with the headline.

---

## 8.3 Core Loop

### Heading

**Security validation, inside the build loop.**

### Loop

```
BUILD → DISCOVER → TEST → INVESTIGATE → VERIFY → FIX → RETEST
```

Each stage should be represented as a compact interactive step.

### Interaction

On hover/focus/click:

- Highlight the current stage.
- Show a one-sentence explanation.
- Avoid changing the page layout dramatically.

### Copy guidance

Keep descriptions concrete.

Example:

**DISCOVER**  
Map routes, forms, APIs, authentication flows, and the application's reachable surface.

---

## 8.4 Why BreachLabs

Explain the product thesis in three or four cards.

### Card 1 — Immediate

Security validation happens immediately after software is built rather than being treated as a late-stage gate.

### Card 2 — Evidence-backed

Scanner signals are correlated with source and runtime evidence before findings are presented as meaningful issues.

### Card 3 — Controlled

The agent operates through allowlisted capabilities, isolated execution, and explicit security boundaries.

### Card 4 — Iterative

The long-term loop connects findings to fixing and retesting rather than stopping at a static report.

---

## 8.5 Capabilities

Show capabilities as compact, scannable cards.

Required capabilities from the existing project description:

- Repository inspection
- Application health validation
- Route/API/form discovery
- Authentication-flow discovery
- Static analysis (SAST)
- Software composition/dependency analysis (SCA)
- Secret detection
- Dynamic web application checks (DAST)
- Browser automation
- AI investigation
- Evidence correlation
- Isolated verification
- Evidence-backed reporting

### UX

Use progressive disclosure if the list becomes visually dense.

Do not make every capability a giant card.

---

## 8.6 Architecture

### Heading

**An investigator connected to controlled security capabilities.**

Represent the existing architecture:

```
Application / Repository
          ↓
   Isolated Environment
          ↓
   Security Orchestrator
          ↓
      AI Agent
          ↓
      MCP Tools
     ↙    ↓     ↘
  SAST   DAST   Browser
     \    ↓     /
       Evidence
          ↓
    Verification
          ↓
      Report
```

### Visual treatment

Use a clean node-and-connector diagram.

Nodes should feel like UI components, not a decorative infographic.

Recommended node states:

- idle
- active
- complete
- warning

Keep connectors subtle. Active paths can use restrained motion.

### Accessibility

Provide an equivalent textual architecture description for screen readers and reduced-motion users.

---

## 8.7 Evidence + Verification

This section should visually answer:

**“How does BreachLabs avoid treating every scanner result as truth?”**

Show a finding lifecycle:

```
Signal
  ↓
Source Evidence
  +
Runtime Evidence
  ↓
AI Investigation
  ↓
Isolated Verification
  ↓
Confidence / Finding
  ↓
Report
```

### UI idea

A split panel:

**Finding**

- Severity
- Affected route/file
- Scanner signal

**Evidence**

- Source location
- Runtime observation
- Verification result

The data can be representative/static for the website. Do not claim that the marketing site itself is running a live scan.

---

## 8.8 Safety

### Heading

**Built for authorized defensive testing.**

Use concise safety principles:

- Test only systems for which authorization exists.
- Prefer isolated, disposable environments.
- Use allowlisted security tools.
- Treat application content as untrusted data.
- Prevent application content from overriding the agent's security policy.
- Do not imply that a clean automated assessment guarantees security.

### Visual

Use a calm, low-drama security panel with status indicators.

Avoid fear-based imagery.

---

## 8.9 Hackathon MVP

BreachLabs is being developed for **VINHACK 2026** during the 30-hour schedule spanning 18–19 September.

Present the MVP as a progress pipeline:

```
Repository
  ↓
Sandbox
  ↓
Build + Health Check
  ↓
Recon
  ↓
SAST + SCA + Secrets + DAST
  ↓
AI Investigation
  ↓
Browser Investigation
  ↓
Verification
  ↓
Evidence-backed Report
```

### UI

A horizontal timeline on desktop and vertical timeline on mobile.

Each step can show:

- status,
- one-line purpose,
- optional implementation note.

Do not invent completion percentages or statuses not supplied by the project.

---

## 8.10 CTA

### Primary message

**Make security part of the build loop.**

### CTA buttons

- View GitHub
- Explore the architecture

### Supporting line

BreachLabs is a defensive security research project. Only assess applications and environments for which you have explicit authorization.

---

## 8.11 Footer

Include:

- BreachLabs
- Short product line: “Build. Break. Verify. Fix.”
- GitHub link
- Architecture link if implemented
- Safety/disclaimer
- Current project status

---

## 9. Design System

## 9.1 Color

Default direction:

- Background: near-white or near-black depending on selected theme.
- Foreground: high-contrast neutral.
- Muted text: neutral gray.
- Borders: subtle neutral.
- Accent: one restrained technical accent.

Support light and dark themes if practical.

Do not use a rainbow palette.

### Status colors

Use semantic status colors only when meaning requires them:

- success
- warning
- error
- informational

Status color must never be the sole way of communicating meaning.

---

## 9.2 Typography

Recommended approach:

- Modern sans-serif for UI/body.
- Optional monospace for code, technical metadata, architecture labels, and evidence values.

Typography hierarchy should be obvious without excessive font weights.

Hero headline should be large but controlled; avoid filling most of the viewport with text.

---

## 9.3 Spacing

Use a consistent Tailwind spacing scale.

Guidelines:

- Large vertical rhythm between major sections.
- Tight spacing inside compact UI components.
- Consistent card padding.
- Avoid arbitrary one-off spacing values unless they solve a real layout problem.

---

## 9.4 Radius

Use restrained corner radii.

- Cards: medium radius.
- Buttons: medium radius.
- Inputs: medium radius.
- Avoid excessive pill shapes except tags/status indicators.

---

## 9.5 Borders and Shadows

Prefer borders and surface contrast over heavy shadows.

Use shadows primarily for floating elements that genuinely need elevation.

---

## 10. Motion Guidelines

Motion should communicate hierarchy and state, not decoration.

### Allowed

- Section fade/slide-in on first viewport entry.
- Workflow progress animation.
- Architecture connector animation.
- Button hover transitions.
- Navigation state transition.
- Subtle background grid movement.
- Reduced-motion alternative.

### Avoid

- Infinite high-speed animations.
- Large parallax effects.
- Excessive blur.
- Motion behind dense text.
- Animations that delay content access.

Implement `prefers-reduced-motion: reduce`.

---

## 11. Responsive Requirements

### Mobile

Target minimum width: 320px.

Requirements:

- No horizontal scrolling.
- Navigation becomes a menu.
- Architecture diagram becomes a vertical flow.
- Workflow cards stack or become horizontally scrollable with accessible controls.
- Buttons remain thumb-friendly.
- Text remains readable without zooming.
- Hero visual is simplified rather than merely scaled down.

### Tablet

Use a two-column composition where appropriate.

### Desktop

Use generous whitespace and a centered content container.

Recommended max content width: approximately 1200–1280px.

---

## 12. Accessibility

Target WCAG 2.2 AA principles.

Required:

- Semantic landmarks.
- Proper heading hierarchy.
- Keyboard navigation.
- Visible focus states.
- Sufficient contrast.
- Accessible mobile menu.
- Button/link semantics.
- Alt text for meaningful imagery.
- Decorative graphics marked appropriately.
- Reduced-motion support.
- No information communicated by color alone.

Architecture and workflow visuals require textual equivalents.

---

## 13. Performance

Target a fast first load.

Requirements:

- Avoid unnecessary JavaScript.
- Prefer CSS/Tailwind for static effects.
- Lazy-load non-critical assets.
- Avoid large background videos.
- Keep animations lightweight.
- Minimize third-party scripts.
- Use local assets where practical.

Suggested targets:

- Lighthouse Performance: 90+
- Lighthouse Accessibility: 95+
- Lighthouse Best Practices: 95+
- Lighthouse SEO: 90+

These are acceptance targets, not guarantees.

---

## 14. SEO / Metadata

Provide:

### Title

**BreachLabs — Give Every Application Its Own Security Engineer**

### Description

**BreachLabs is an autonomous AI application-security engineer for continuous, evidence-backed security validation inside the software-building loop.**

Include:

- Open Graph metadata
- Twitter/X card metadata
- canonical URL placeholder
- favicon/site icon
- semantic page structure

Do not add keyword stuffing.

---

## 15. Flask Backend Requirements

Create a self-contained Flask application under `website/`.

Suggested structure:

```
website/
├── app.py
├── requirements.txt
├── README.md
├── templates/
│   ├── base.html
│   └── index.html
├── static/
│   ├── css/
│   │   └── input.css
│   ├── js/
│   │   └── main.js
│   └── img/
├── components/
│   └── ...
└── PRD.md
```

The exact structure may vary if the implementation remains isolated and maintainable.

### Flask behavior

- `GET /` renders the website.
- Static files served from `website/static/`.
- No import-time modification of parent project state.
- No coupling to existing BreachLabs application modules unless explicitly required later.
- Development server must be runnable independently.

---

## 16. Frontend Component Requirements

Implement a small reusable design system rather than styling every section independently.

### Required primitives

**Button**

Variants:

- primary
- secondary
- ghost

States:

- default
- hover
- focus
- disabled

**Badge**

Examples:

- MVP
- AI Agent
- MCP
- SAST
- DAST
- Verified

**Card**

Variants:

- default
- elevated
- interactive

**Section heading**

Supports:

- eyebrow
- heading
- description

**Workflow step**

Supports:

- number/icon
- title
- description
- state

**Architecture node**

Supports:

- label
- type
- state
- description

---

## 17. Content Rules

The copy should be:

- concise,
- technically accurate,
- confident,
- understandable,
- evidence-oriented.

Prefer:

> “Correlates scanner output with source and runtime evidence.”

Avoid:

> “Our revolutionary AI destroys every vulnerability before hackers can blink.”

Never claim:

- complete security,
- zero vulnerabilities,
- guaranteed prevention,
- autonomous unrestricted hacking,
- guaranteed compliance,
- guaranteed detection.

---

## 18. Demo / Interactive Prototype

If a demo surface is implemented, it should use deterministic static/mock data.

Suggested mock assessment:

**Target:** Demo Web Application

Stages:

1. Environment ready
2. Application healthy
3. Routes discovered
4. Static analysis complete
5. Dependencies checked
6. Secrets checked
7. Dynamic checks complete
8. Finding investigated
9. Finding verified
10. Report generated

The interface should clearly indicate that this is a **demo/prototype assessment** unless a real backend integration is later implemented.

---

## 19. Error and Empty States

Although the MVP is primarily a marketing/product site, interactive components must define:

### Loading

Use restrained skeletons or status indicators.

### Error

Example:

> Something went wrong while loading this view.

Provide a retry action where appropriate.

### Empty

Example:

> No assessment data is available yet.

Avoid exposing stack traces or sensitive backend details.

---

## 20. Security Requirements

The website itself must follow defensive web-development practices.

- Escape user-controlled content.
- Do not expose secrets in templates or static files.
- Do not commit environment secrets.
- Use secure cookie configuration if sessions are introduced.
- Apply appropriate security headers where practical.
- Avoid inline scripts when CSP compatibility would be affected.
- Validate any future form input server-side.
- Do not add arbitrary command execution endpoints.
- Do not connect the public site directly to a security scanner without explicit authorization and isolation.

---

## 21. Repository Isolation Rule

This is a hard requirement.

### Allowed

Create:

```
website/
```

and all website-specific files beneath it.

### Not allowed

- Editing existing `breachlabs/` files.
- Editing the existing root `PRD.md`.
- Editing existing project configuration merely to make the website work.
- Moving existing files.
- Renaming existing files.
- Reformatting existing files.
- Changing existing application behavior.

If integration with the existing project becomes necessary, document the integration requirement instead of modifying the existing code in this phase.

---

## 22. Suggested Git Workflow

Implement the website on a dedicated branch.

Suggested branch:

```
website/<implementation-name>
```

All website changes should remain isolated to `website/`.

A later PR can merge the website implementation after review.

---

## 23. Acceptance Criteria

### Product

- [ ] Visitor understands BreachLabs within the first screen.
- [ ] Product thesis is clearly communicated.
- [ ] Core security loop is understandable without reading the entire page.
- [ ] Architecture is represented accurately.
- [ ] Safety/authorization principles are visible.
- [ ] Hackathon MVP flow is represented without invented progress data.
- [ ] GitHub CTA is present.

### Visual

- [ ] Minimal, premium developer-tool aesthetic.
- [ ] Consistent spacing and typography.
- [ ] Restrained use of accent color.
- [ ] shadcn-style component anatomy.
- [ ] Selective Magic UI-style motion.
- [ ] No generic cybersecurity cliché imagery.
- [ ] No excessive gradients/glassmorphism.

### Technical

- [ ] Flask application runs independently from `website/`.
- [ ] TailwindCSS is used.
- [ ] Semantic HTML is used.
- [ ] Existing project files are untouched.
- [ ] Responsive at 320px+.
- [ ] Keyboard navigation works.
- [ ] Reduced-motion support exists.
- [ ] No secrets are committed.
- [ ] No arbitrary command execution is introduced.

### Quality

- [ ] Lighthouse Performance ≥ 90 target.
- [ ] Lighthouse Accessibility ≥ 95 target.
- [ ] Lighthouse Best Practices ≥ 95 target.
- [ ] Lighthouse SEO ≥ 90 target.
- [ ] No console errors in normal operation.
- [ ] No broken internal links.
- [ ] No horizontal overflow on supported viewport sizes.

---

## 24. Recommended Build Order

### Phase 1 — Foundation

1. Create isolated `website/` Flask app.
2. Establish Tailwind configuration and design tokens.
3. Create base template and responsive container.
4. Implement reusable UI primitives.

### Phase 2 — Core story

5. Build navigation.
6. Build hero.
7. Build core loop.
8. Build capabilities.
9. Build architecture.

### Phase 3 — Trust

10. Build evidence/verification section.
11. Build safety section.
12. Build hackathon MVP section.

### Phase 4 — Polish

13. Add restrained motion.
14. Add responsive refinements.
15. Add accessibility refinements.
16. Add SEO/social metadata.
17. Run performance and visual QA.

---

## 25. Definition of Done

The website is ready for review when:

- It runs independently through Flask.
- It is entirely contained under `website/`.
- The existing BreachLabs application has not been modified.
- The core product story is understandable without technical onboarding.
- Architecture and security workflow are visually clear.
- UI components share a coherent design system.
- Motion is subtle and accessible.
- The site works on mobile, tablet, and desktop.
- Accessibility and performance checks meet the stated targets or have documented exceptions.
- The repository diff contains only intentional website additions.

---

## 26. Future Roadmap

Potential post-MVP enhancements:

1. Live assessment-status integration.
2. Interactive evidence explorer.
3. Real report viewer.
4. Assessment history.
5. Finding detail pages.
6. Authentication for authorized users.
7. Team/project workspaces.
8. Secure scan-launch workflow.
9. Real-time event stream.
10. Developer fix/retest integration.

These are future capabilities and should not be implied as currently available.

---

## 27. Final Design North Star

The website should feel like **BreachLabs itself**:

> **Calm on the surface. Rigorous underneath.**

It should communicate serious engineering through typography, information hierarchy, architecture, evidence, and restrained interaction — not through visual noise.

The best version of the page should look like a product that security engineers would trust and developers would actually want to use.

---

## Appendix A — Existing Project Facts Used in This PRD

The website content is based on the existing BreachLabs project description:

- BreachLabs is an autonomous AI application-security engineer.
- Core loop: BUILD → DISCOVER → TEST → INVESTIGATE → VERIFY → FIX → RETEST.
- It combines an AI security agent with controlled MCP tools, deterministic security scanners, browser automation, and isolated execution environments.
- Capabilities include repository inspection, application validation, route/form/API/authentication discovery, SAST, dependency checks, secret checks, DAST, browser exploration, AI investigation, evidence correlation, isolated verification, and reporting.
- Safety model emphasizes authorized defensive testing, isolated disposable environments, allowlisted tools, and treating application content as untrusted data.
- Hackathon: VINHACK 2026, 18–19 September.
- MVP flow: Repository → Sandbox → Build + Health Check → Recon → SAST + SCA + Secrets + DAST → AI Investigation → Browser Investigation → Verification → Evidence-backed Report.

No claim in this website PRD should be expanded beyond what the project actually implements.

---

**End of PRD**
