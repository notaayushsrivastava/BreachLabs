# BreachLabs Website PRD

## Product Requirements Document

**Project:** BreachLabs Website  
**Brand line:** Build. Break. Verify. Fix.  
**Primary product message:** Give every application its own security engineer.  
**Document status:** Implementation-ready PRD  
**Website implementation boundary:** `website/` only  
**Frontend architecture:** Static HTML + CSS + vanilla JS  
**Backend architecture:** Flask + Jinja  
**Styling:** Tailwind CSS, with the visual language of shadcn/ui and Magic UI  

---

# 1. Executive Summary

BreachLabs is an autonomous AI application-security engineer that inspects, tests, investigates, verifies, explains, fixes, and retests AI-built software.

The website must present BreachLabs as a serious security-engineering product rather than a generic AI landing page or a conventional vulnerability-scanner dashboard. The experience should combine a high-end editorial interface with an observable security assessment workflow.

The MotionSites reference prompt supplied for the hero is the visual foundation of this PRD. Its exact constraints for the first viewport must be preserved. The rest of the website should extend the same visual system instead of introducing unrelated page designs.

The website should feel like one continuous product experience:

**Hero → signal → workflow → reconnaissance → testing → investigation → verification → evidence → remediation → retest → architecture → security model → product capabilities → demo → CTA**

Scrolling should not feel like moving between disconnected cards. It should feel like moving deeper into the BreachLabs security engine.

---

# 2. Hard Implementation Constraints

## 2.1 Repository isolation

**Do not modify the existing BreachLabs application.**

All website work must be contained inside:

```text
website/
```

The existing agent, MCP implementation, scanner integrations, scripts, application runtime, demo targets, configuration, tests, and unrelated project files must remain untouched unless a future task explicitly requests a change outside `website/`.

The website should be independently runnable from its own directory.

## 2.2 Frontend technology

Use:

- HTML
- Jinja templates
- Tailwind CSS
- Vanilla JavaScript
- CSS animations/transitions where appropriate

Do not introduce React, Next.js, Vue, Svelte, or another SPA framework merely to reproduce component aesthetics from shadcn/ui or Magic UI.

shadcn/ui and Magic UI should be treated as **design/component references and interaction patterns**, adapted into framework-neutral HTML/CSS/JS.

## 2.3 Backend technology

Use Flask for:

- route handling
- Jinja rendering
- safe demo-data endpoints
- health checking
- future integration boundaries
- server-side configuration

Marketing content should remain mostly server-rendered.

## 2.4 Existing MotionSites visual prompt

The supplied MotionSites prompt is authoritative for the hero's core visual behavior. The following must be preserved rather than casually redesigned:

- single-viewport, full-bleed video-background hero
- exact background video URL
- black page/background treatment
- Inter for UI
- BubbledotICG-FinePos for display typography
- Geist Pixel Circle as fallback display font
- Font Awesome 6.5.2 for enterprise brand icons
- exact CSS variable values from the source prompt
- three-region composition: header, hero, stats footer
- centered desktop header
- white circular logo button
- white navigation pill
- dark Sign in pill
- trust row with Microsoft/Amazon/Google icons
- solid white headline
- exact headline copy:
  - `Intelligence`
  - `Designed To Evolve`
- exact subhead copy from the supplied prompt
- `Get Started` CTA
- exact four metric values and labels
- entrance animations and mobile behavior
- reduced-motion behavior
- no gradient animation on the headline
- no hero card grid
- no heavy nav/logo shadow
- no full-bleed white trust circles

Where this PRD expands the site beyond the first viewport, those new sections must visually inherit the same typography, spacing, motion, contrast, radius, and compositional language.

---

# 3. Design North Star

The website should feel like a **security engineer at work**, not a marketing template.

The interface should communicate:

- precision
- observability
- controlled power
- technical depth
- confidence without hype
- evidence over speculation
- deliberate motion
- clear hierarchy

The website should avoid:

- generic AI purple/violet/indigo branding
- excessive gradients
- noisy glassmorphism
- floating neon blobs
- giant decorative 3D objects with no product meaning
- excessive rounded cards
- repetitive feature-card grids
- marketing-copy walls
- constant background motion
- fake terminal output that says nothing meaningful
- unnecessary interaction for interaction's sake
- excessive pills
- oversized dashboard chrome on public pages

---

# 4. Primary Audience

The website must serve several audiences without becoming fragmented.

### Hackathon judges

Need to understand the product quickly, see the technical architecture, and understand what distinguishes an autonomous security workflow from a collection of scanners.

### Developers

Need to understand where BreachLabs fits into the build → test → fix lifecycle.

### Security engineers

Need concrete language around static analysis, dynamic analysis, browser testing, evidence, verification, scope, isolation, and limitations.

### Technical evaluators

Need an accurate picture of the orchestrator, AI agent, MCP tools, security scanners, sandbox, evidence pipeline, and future extensibility.

### General visitors

Need to understand what BreachLabs does without needing security expertise.

---

# 5. Core Product Narrative

The website must repeatedly reinforce one simple idea:

> Software is being built faster. Security validation needs to move into the same loop.

BreachLabs closes that loop with:

```text
BUILD
  ↓
DISCOVER
  ↓
TEST
  ↓
INVESTIGATE
  ↓
VERIFY
  ↓
FIX
  ↓
RETEST
```

This lifecycle is the site's primary storytelling device.

The AI should not be represented as magical omniscience. The website should communicate that:

**AI investigates. Deterministic tools measure. Evidence connects them. Verification increases confidence.**

---

# 6. Information Architecture

The website should support the following routes:

```text
/
/how-it-works
/architecture
/security
/capabilities
/demo
/about
```

Optional future routes:

```text
/reports
/findings
/report/<id>
/findings/<id>
/docs
```

The public site must be useful without authentication. Any authenticated product dashboard must remain architecturally separate from this marketing website unless explicitly added later.

---

# 7. Global Experience Model

## 7.1 Full-page composition

The first viewport follows the exact MotionSites composition.

After the hero, the website becomes a long-form, scroll-driven narrative.

Each section should feel like the next stage of one security assessment.

Use:

- generous vertical spacing
- large typographic hierarchy
- full-width visual moments
- restrained content groupings
- occasional split layouts
- horizontal rule transitions
- sticky visual storytelling where useful
- scroll-linked progress indicators where useful
- sparse, meaningful animation

Do not turn every section into three/four/six cards.

## 7.2 Background progression

The site may transition between very dark neutral surfaces instead of keeping a single flat black forever.

Recommended tonal sequence:

```text
#000000
→ #050505
→ #0A0A0A
→ #111111
→ #090909
→ #000000
```

Transitions should be subtle enough that the website still feels like one environment.

## 7.3 Persistent visual language

Every section should reuse a small system of:

- display headline typography
- compact uppercase eyebrow labels
- thin separators
- monospace technical metadata
- small status indicators
- restrained accent color
- subtle motion
- precise alignment

---

# 8. Typography System

## UI Font

Use the exact Inter stack from the MotionSites prompt:

```css
--font-sans: "Inter", "Segoe UI", system-ui, sans-serif;
```

Google Fonts source:

```html
<link
  href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap"
  rel="stylesheet"
/>
```

## Display Font

Use the exact BubbledotICG-FinePos source:

```html
<link
  href="https://db.onlinewebfonts.com/c/8cb707a9b8a73f8a7403336b861c3074?family=BubbledotICG-FinePos"
  rel="stylesheet"
/>
```

Display stack:

```css
--font-display: "BubbledotICG-FinePos", "Geist Pixel Circle", monospace;
```

## Local fallback font

Use:

```text
fonts/GeistPixel-Circle.woff2
```

with:

- weight 400
- `font-display: swap`

## Typography behavior

Display typography should be used for:

- hero headline
- major section headlines
- numerical/security signal moments
- selected architectural labels

Inter should be used for:

- navigation
- body copy
- controls
- metadata
- buttons
- labels

Monospace treatment may be used for:

- routes
- file paths
- finding IDs
- scan events
- commands
- timestamps
- code snippets
- verification states

---

# 9. Exact Color Variables

Preserve the MotionSites variables exactly where they apply:

```css
--bg: #000000;
--text: #ffffff;
--muted: #8e8e8e;
--nav-text: #2e2e2e;
--pill-dark: #28282a;
--sign-in-text: #c8c8c8;
--nav-shadow: 0 4px 14px rgba(0, 0, 0, 0.16);
--trust-bg: #28282a;
--trust-border: rgba(255, 255, 255, 0.4);
--trust-text: #c4c2c3;
```

The website may introduce additional semantic variables for security states, but they must remain restrained.

Suggested semantic usage:

- neutral: white/gray
- information: controlled cool accent
- confirmed: muted green
- warning: muted amber
- critical: restrained red

Security state colors should never become a rainbow dashboard.

---

# 10. Hero: Exact MotionSites Specification

This section preserves the user-supplied prompt.

## Background video

Use this exact CloudFront URL:

```html
<video class="bg-video" autoplay muted loop playsinline>
  <source
    src="https://d8j0ntlcm91z4.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/hf_20260809_012548_ef22562c-c0ae-4816-ad9d-f8922af4e6a7.mp4"
    type="video/mp4"
  />
</video>
```

Requirements:

- `position: absolute`
- `inset: 0`
- `object-fit: cover`
- `pointer-events: none`
- `z-index: 0`
- parent `.bg` is black
- `overflow: hidden`

## Page shell

```css
.page {
  display: flex;
  flex-direction: column;
  height: 100vh;
  height: 100dvh;
  overflow: hidden;
  padding: clamp(16px, 2.4vh, 28px) clamp(14px, 3vw, 32px);
}
```

Header, hero, stats footer, and mobile menu remain above the video with `z-index: 1`.

## Header

Desktop:

- centered row
- max-width `720px`
- gap `clamp(18px, 2.8vw, 28px)`
- circular logo
- white navigation pill
- dark Sign in pill

Logo:

- circular button `clamp(40px, 4.4vw, 46px)`
- `border-radius: 50%`
- white background
- soft shadow `--nav-shadow`
- `assets/logo.webp`
- image icon scaled to 72%
- centered with CSS grid
- hover scale 1.04

Navigation:

- white pill
- height `clamp(44px, 5.2vw, 48px)`
- max-width `430px`
- padding `4px 8px`
- radius `999px`
- Home / Product / Case Studies / Contact from the source prompt may be mapped to BreachLabs information architecture while preserving the same visual treatment.
- default opacity 0.5
- hover opacity 0.75
- active opacity 1
- active indicator is three 3×3px black dots

Sign in:

- dark `#28282a`
- text `#c8c8c8`
- same height as nav
- radius 999
- soft shadow
- hover background `#323234`
- hover text white
- hover translateY(-1px)

Entrance animation:

```text
slideDown 0.7s cubic-bezier(0.22, 1, 0.36, 1)
```

## Trust row

Copy:

```text
Trusted by 2000+ Enterprises
```

The trust row must retain the exact visual behavior from the supplied prompt:

- `--trust-size: clamp(36px, 4.5vw, 42px)`
- 34px at ≤420px
- dark avatar ring
- 1px translucent white border
- 5px padding
- inner white circle
- Microsoft icon
- Amazon icon
- Google icon
- overlapping avatar rings
- trust pill overlapping the final avatar
- subtle hover lift

Important: use this only as the visual treatment specified by the supplied prompt. It must not imply an actual customer relationship unless the project has verified evidence for that claim.

For BreachLabs, a more accurate future production alternative is a product-signal row such as:

```text
Open Source · GitHub · MCP · SAST · DAST · Browser Automation
```

However, the hero implementation should preserve the supplied prompt exactly unless the copy is explicitly changed later.

## Headline

Exact two-line structure from the source prompt:

```text
Intelligence
Designed To Evolve
```

For the BreachLabs site, this may be retained as the visual hero headline while the supporting eyebrow and supporting copy establish BreachLabs as the security product.

Rules:

- BubbledotICG-FinePos
- solid white
- no gradient
- no shimmer
- no animated LED scan
- desktop `clamp(28px, 6.2vw, 80px)`
- desktop letter spacing `-0.04em`
- ≤720px `-0.08em`
- ≤420px `-0.09em`
- line-height 1.12 desktop
- 1.05 / 1.04 at smaller breakpoints
- `white-space: nowrap`
- overflow hidden

Line entrance:

```text
headlineFade 0.85s cubic-bezier(0.22, 1, 0.36, 1)
```

Delays:

- line 1: `0.12s`
- line 2: `0.3s`

## Subhead

Preserve exact supplied copy:

```text
Build applications that reason, adapt and collaborate using a modular
AI platform designed for production.
```

For BreachLabs, the product-specific secondary statement should be introduced immediately below or as an adjacent context line, for example:

```text
An autonomous security engineer for the software you just built.
```

This secondary statement must remain concise and should not replace the supplied visual prompt copy without an explicit design change.

Subhead rules:

- max-width `min(500px, 92%)`
- Inter
- source prompt font-size formula preserved
- `#d0d0d0`
- opacity 0.8
- line-height 1.55
- weight 400
- reveal delay `0.28s`

## CTA

Primary text:

```text
Get Started
```

The CTA must use the source prompt sizing, white pill styling, black text, soft white glow, hover lift, and `revealPulse` animation.

The action should route to the most relevant first product step, such as a safe Demo or How It Works section.

## Stats footer

Preserve exactly four metrics:

| Icon glyph | Target | Suffix | Decimals | Label |
|---|---:|---|---:|---|
| `<` | 120 | `ms` | 0 | Inference Time |
| `%` | 99.99 | `%` | 2 | Platform Uptime |
| `*` | 24 | `/7` | 0 | Autonomous Runtime |
| `#` | 2.4 | `M` | 1 | Context Windows |

These are presentation metrics from the source prompt. They must not be represented as verified BreachLabs operating claims unless the project has actually measured and approved them. For production copy, replace any unverified metric with BreachLabs-specific measured values or clearly mark the data as illustrative.

Count-up behavior from the source prompt:

- easeOutCubic
- 1500 + i×80ms duration
- 480 + i×90ms start offset
- once via IntersectionObserver
- threshold `0.25`

## Shared animation

`.anim` elements:

- start opacity 0
- `translateY(22px) scale(0.98)`
- `blur(6px)`
- animate with `reveal 0.85s cubic-bezier(0.22, 1, 0.36, 1)`
- delay via `--d`

Reduced motion:

- kill animations
- show final state
- headline remains solid white

## Mobile

At ≤720px:

- hide desktop nav and Sign in
- header becomes space-between
- logo 48×48
- circular burger 48×48
- dark burger background
- 3 white 18×1.5px bars

Open state:

- white circular button
- bars become black X

Overlay:

- fixed full screen
- `rgba(0,0,0,0.62)`
- blur 6px
- `overlayIn 0.28s`

Menu sheet:

- centered under header
- white
- radius 28px
- `22px 18px 20px` padding
- shadow `0 20px 60px rgba(0,0,0,0.45)`
- `menuIn 0.38s`

Menu links:

- Home
- Product
- Case Studies
- Contact
- full-width Sign in
- staggered `linkIn`
- three-dot active indicator

JS behavior:

- toggle `aria-expanded`
- toggle `hidden`
- toggle `body.menu-open`
- close overlay click
- close Escape
- close link click
- close on resize >720px

Stats become 2 columns.

---

# 11. Scroll Experience After the Hero

The website must continue the MotionSites visual language rather than stopping at the hero.

The scroll experience should behave like a guided security assessment.

## Scroll principle

Each section answers one question:

```text
What is this?
→ How does it work?
→ What does it inspect?
→ How does it investigate?
→ How does it verify?
→ What evidence does it produce?
→ How does it help fix the issue?
→ How does it retest?
→ How is it built safely?
→ What can I see in the product?
```

## Scroll motion principles

Use animation to explain structure.

Recommended effects:

- section title reveal
- horizontal progress line growth
- moving assessment cursor
- path tracing through architecture
- number transitions
- small terminal/log updates
- sticky left-side stage labels
- code-line highlighting
- evidence fragments resolving into a finding
- finding state changing from detected → investigated → verified
- report document assembling over time

Avoid:

- giant parallax scenes that distract from content
- constant particle fields
- infinite floating icons
- animation on every DOM element
- aggressive zooming
- content hidden behind long animation delays

---

# 12. Section 01 — Product Signal

Immediately after the hero, create a short transition section.

Purpose:

Establish BreachLabs as the bridge between software creation and software assurance.

Headline direction:

```text
Security should run
where software runs.
```

Supporting copy should explain that BreachLabs enters the build loop instead of treating security as a separate end-of-cycle task.

Visual:

A thin horizontal assessment line that progresses through:

```text
Repository → Environment → Assessment → Evidence
```

The line should begin static and animate into the next section as the user scrolls.

---

# 13. Section 02 — The Security Loop

Create a major full-width narrative section.

Show:

```text
BUILD
DISCOVER
TEST
INVESTIGATE
VERIFY
FIX
RETEST
```

Each stage should occupy a strong typographic position rather than a small card.

Interaction options:

- scroll changes active stage
- active stage enlarges subtly
- supporting copy changes alongside it
- technical metadata appears in monospace
- an animated progress line connects stages

Example stage content:

### Build
Create or receive the application.

### Discover
Map routes, forms, APIs, authentication flows, and exposed surfaces.

### Test
Run deterministic SAST, dependency, secret, and DAST checks.

### Investigate
Use AI reasoning to correlate tool results with source and runtime evidence.

### Verify
Perform targeted checks to distinguish actionable findings from speculation.

### Fix
Explain remediation and, where explicitly supported, prepare a targeted fix.

### Retest
Repeat the relevant assessment to verify that the issue is actually resolved.

---

# 14. Section 03 — From Repository To Attack Surface

Visualize the beginning of an assessment.

Sequence:

```text
Repository
   ↓
Build
   ↓
Health Check
   ↓
Reconnaissance
   ↓
Attack Surface
```

Use a dark technical panel or inline visual console, not a conventional rounded card.

Example signals:

```text
routes found      14
forms discovered   3
APIs observed      9
auth flow          1
static assets     37
```

These should be clearly labeled as illustrative when they are not live data.

Motion:

- lines appear progressively
- cursor moves down the assessment output
- route paths highlight on discovery
- attack-surface summary assembles at the bottom

---

# 15. Section 04 — Deterministic Security Tools

Purpose:

Explain that BreachLabs does not rely on an LLM alone.

Primary visual:

A horizontal pipeline of tools feeding one evidence stream:

```text
SAST ─────┐
SCA ──────┤
Secrets ──┼──→ Evidence Graph
DAST ─────┤
Browser ──┘
```

Describe:

- static source analysis
- dependency/security hygiene checks
- secret detection
- dynamic application testing
- browser-based workflow investigation

The design should visually separate **measurement** from **reasoning**.

Headline:

```text
AI does not replace the tools.
It makes the tools useful together.
```

---

# 16. Section 05 — AI Investigation

This is one of the most important sections.

Show a finding evolving through investigation.

Example:

```text
Signal detected
      ↓
Source context
      ↓
Runtime context
      ↓
Related evidence
      ↓
Investigation
      ↓
Confidence
```

The visual should show an AI investigator reasoning over evidence, but must avoid exposing chain-of-thought or implying privileged internal reasoning.

The product should communicate outcomes, evidence references, checks performed, and confidence rather than private model reasoning.

Use compact labels such as:

```text
SOURCE MATCHED
RUNTIME OBSERVED
REPRODUCTION ATTEMPTED
VERIFICATION PENDING
```

---

# 17. Section 06 — Verification

Purpose:

Show the distinction between “a scanner reported something” and “BreachLabs verified something.”

Visual concept:

A finding begins as:

```text
DETECTED
```

then passes through:

```text
INVESTIGATING
```

then:

```text
VERIFIED
```

or:

```text
UNCONFIRMED
```

The UI should make uncertainty visible rather than forcing every signal into a critical finding.

Headline:

```text
Evidence before certainty.
```

---

# 18. Section 07 — Evidence-Backed Findings

Create an editorial case-study-like section around one finding.

Show:

- finding title
- severity
- confidence
- affected route/file
- evidence excerpt
- reproduction/verification status
- impact
- remediation
- retest state

Example structure:

```text
FINDING BL-0142

Sensitive Data Exposure

Severity     HIGH
Confidence   VERIFIED
Surface      GET /api/profile

Evidence
────────────
Source path: app/routes/profile.py
Runtime:     observed response field
Browser:     authenticated request reproduced

Status
[ VERIFIED ]
```

This can be presented as a single large artifact with side notes rather than many cards.

---

# 19. Section 08 — Fix And Retest

The user should see the security loop close.

Sequence:

```text
Finding
  ↓
Remediation
  ↓
Patch
  ↓
Retest
  ↓
Verified resolved
```

Do not imply that automatic code modification is universally available. Describe it as a supported or future capability according to actual project status.

Where the current MVP supports only remediation guidance, say so.

Visual:

Split source view:

```text
BEFORE                 AFTER
---------              ---------
unsafe behavior        corrected behavior
```

Then show:

```text
RETEST: PASS
```

The animation should feel like an engineering workflow completing, not a celebratory confetti effect.

---

# 20. Section 09 — Architecture

Create a major architecture section.

Core diagram:

```text
Application / Repository
          ↓
   Isolated Environment
          ↓
 Security Orchestrator
          ↓
      AI Agent
          ↓
      MCP Tools
      ↙   ↓   ↘
   SAST  DAST  Browser
      \    |    /
        Evidence
           ↓
      Verification
           ↓
         Report
```

Each node should have an accessible text description.

Visual treatment:

- thin connection lines
- subtle animated traversal path
- active node highlight
- monospace labels
- no huge 3D diagram required

When the user scrolls through the architecture, the active node should correspond to a short explanatory block.

---

# 21. Section 10 — MCP And Tool Boundaries

Explain that BreachLabs uses controlled tools rather than arbitrary unrestricted execution.

Show tool categories:

```text
Repository
Application
Static Analysis
Dynamic Analysis
Browser
Evidence
Reporting
```

The visual should show an explicit boundary around the tool system.

Headline:

```text
Power comes with boundaries.
```

Supporting message:

- scoped execution
- allowlisted security tools
- isolated environments
- application content treated as untrusted
- evidence collection
- explicit authorization

---

# 22. Section 11 — Security Model

This page/section must be unusually clear for a security product.

Topics:

### Authorized scope

BreachLabs is designed for authorized defensive testing.

### Isolation

Assessments should run in isolated/disposable environments where applicable.

### Tool control

Security capabilities should be exposed through controlled, explicit tools.

### Untrusted application content

Application output, source content, web pages, logs, and discovered prompts must not override agent policy.

### Secrets

Website pages must never expose live secrets or credentials.

### Limitations

Automated assessment can miss vulnerabilities. A clean report is not a guarantee of complete security.

Design this section as a confidence-building technical explanation, not a generic “we take security seriously” statement.

---

# 23. Section 12 — Capability Explorer

Create a deep capability section without reverting to a repetitive card grid.

Recommended layout:

A vertical list or sticky-scrolling index:

```text
01  Repository Intake
02  Environment Validation
03  Reconnaissance
04  SAST
05  Dependency Analysis
06  Secret Detection
07  DAST
08  Browser Investigation
09  AI Triage
10  Evidence Correlation
11  Targeted Verification
12  Reporting
13  Fix Guidance
14  Retesting
```

Clicking or scrolling a capability should update a large visual area.

This preserves information density while keeping the visual design minimal.

---

# 24. Section 13 — Demo Experience

A public demo must be deterministic and safe.

The demo may show:

```text
Upload/Select Demo Target
       ↓
Start Assessment
       ↓
Observe Discovery
       ↓
Observe Scanners
       ↓
Observe Investigation
       ↓
View Verified Findings
       ↓
View Report
```

Do not allow arbitrary public scanning of external targets from the marketing website.

Do not accept arbitrary shell commands.

Do not expose unrestricted exploit capabilities.

Use a controlled vulnerable demo application when the project includes one.

If the live product backend is unavailable, use clearly labeled deterministic mock data rather than a fake “live” scan.

---

# 25. Section 14 — Reports

Future report preview should feel like a technical artifact.

Use:

- finding IDs
- severity
- confidence
- timestamps
- affected surface
- evidence
- remediation
- verification
- status

Report preview should have a print/export-friendly visual structure.

Future route:

```text
/report/<id>
```

Potential future PDF export can be added without changing the marketing site's design system.

---

# 26. Section 15 — About / Hackathon Context

The About page should explain:

- what BreachLabs is
- why it exists
- the build/break/verify/fix concept
- hackathon context where relevant
- current MVP boundaries
- roadmap
- repository destination

Keep this page technical and concise.

Avoid a generic “our story” startup narrative.

---

# 27. Section 16 — Final CTA

The final section should echo the hero.

Headline direction:

```text
Give every application
its own security engineer.
```

Supporting line:

```text
Build faster. Validate earlier. Ship with evidence.
```

Actions:

- View Demo
- Explore Architecture
- GitHub

Visual treatment:

A large typographic end state with a restrained animated assessment line returning to the beginning of the product loop.

The website should visually close the loop:

```text
BUILD → ... → RETEST → BUILD
```

---

# 28. Navigation Model

Desktop navigation can retain the MotionSites white pill treatment while using BreachLabs destinations.

Recommended labels:

```text
Home
Product
Architecture
Security
About
```

Primary action:

```text
Demo
```

The active route should use the same three-dot indicator defined by the source prompt.

Do not add more top-level navigation items merely because more pages exist. Secondary pages can be accessed through section CTAs and footer navigation.

---

# 29. Footer

The footer should be minimal.

Include:

- BreachLabs mark
- `Build. Break. Verify. Fix.`
- GitHub
- Product
- Architecture
- Security
- About
- legal/safety note where required
- copyright/year

Use a compact dark composition with thin dividers.

Avoid a large multi-column enterprise footer.

---

# 30. shadcn/ui Adaptation

The website should use shadcn/ui principles rather than blindly importing the framework.

Adapt these patterns:

- Button
- Navigation Menu
- Badge
- Tabs
- Accordion
- Dialog
- Sheet
- Tooltip
- Separator
- Scroll Area
- Progress

Implementation rules:

- accessible semantics
- keyboard support
- visible focus states
- restrained borders
- clear states
- consistent radius
- no component should feel copied from a template library without being styled into the BreachLabs system

Mobile navigation should behave like a shadcn Sheet even though the implementation is vanilla JS.

---

# 31. Magic UI Adaptation

Use Magic UI as inspiration for premium micro-interactions.

Suitable patterns:

- animated border accents
- subtle shimmer on loading/progress states
- beam/path animations for architecture
- spotlight effects around active evidence
- terminal-style typing
- number counters
- scroll-based reveal
- small orbital/connection motion

Do not use every available effect.

Rule:

> One strong motion idea per section is better than ten weak effects.

---

# 32. Tailwind Requirements

Tailwind is the main styling layer.

Create a coherent token system for:

- background
- foreground
- muted text
- borders
- accent
- success
- warning
- danger
- radius
- spacing
- typography
- motion timing

Recommended reusable Jinja partials:

```text
components/nav.html
components/button.html
components/status.html
components/section-label.html
components/metric.html
components/evidence-row.html
components/finding.html
components/architecture-node.html
components/footer.html
```

Avoid putting complete page layouts into one enormous template.

---

# 33. JavaScript Architecture

Vanilla JS should be modular even without a framework.

Recommended structure:

```text
static/js/
├── main.js
├── nav.js
├── motion.js
├── counters.js
├── workflow.js
├── architecture.js
├── demo.js
└── reduced-motion.js
```

The implementation can consolidate these files if the final codebase remains clean and maintainable.

JavaScript should primarily handle:

- mobile nav
- intersection observers
- scroll state
- counters
- active workflow stage
- architecture path state
- demo interactions
- accessible dialogs/sheets
- progressive enhancement

The site must remain understandable if JavaScript fails.

---

# 34. Scroll-Driven Interaction Specification

## 34.1 Section reveal

Use the existing reveal animation language:

```text
opacity: 0
transform: translateY(22px) scale(0.98)
filter: blur(6px)
```

Then transition to the final state.

Keep duration around `0.85s` with the existing easing unless a section needs a shorter interaction.

## 34.2 Scroll progress

Optional global progress indicator:

- 1px or 2px line
- viewport top edge or side edge
- controlled by scroll position
- no thick progress bar

## 34.3 Sticky narrative

For complex sections such as the security loop and architecture:

- keep the current stage/title sticky
- let detailed content change as the user scrolls
- use viewport intersection to update state

## 34.4 Reduced motion

All scroll-linked effects must degrade gracefully.

When:

```css
@media (prefers-reduced-motion: reduce)
```

then:

- remove transitions where possible
- reveal content immediately
- stop looping decorative animation
- keep essential state indicators visible

---

# 35. Content And Copy Guidelines

Tone:

- technical
- direct
- precise
- confident
- calm

Use verbs:

- inspect
- discover
- test
- investigate
- verify
- explain
- fix
- retest

Avoid:

- revolutionary
- magic
- unstoppable
- military-grade
- impossible to hack
- zero-day hunter unless literally accurate
- fully autonomous in contexts where human authorization or oversight is still required
- guaranteed secure

Never exaggerate performance metrics, security coverage, customer adoption, or production readiness.

---

# 36. Security And Trust Requirements

The public website is itself part of the security story.

Requirements:

- never leak environment variables
- never render server secrets
- never embed real credentials in examples
- sanitize user/demo content before rendering
- avoid unsafe HTML injection
- apply appropriate response headers
- use CSP where compatible with required CDN assets
- protect forms from obvious abuse
- disable arbitrary command execution from web requests
- never expose an unrestricted scanning endpoint
- keep mock/demo findings isolated from production findings

The website must clearly communicate that any scanning performed by BreachLabs is authorized and scoped.

---

# 37. Accessibility Requirements

The site must:

- use semantic HTML
- use correct heading hierarchy
- provide alt text where imagery is meaningful
- use empty alt text for purely decorative images
- support keyboard navigation
- provide visible focus
- expose state using ARIA where appropriate
- make mobile menu state understandable to assistive technology
- avoid conveying critical information using color alone
- respect reduced motion
- maintain usable text sizes

The video background must never be required to understand the content.

---

# 38. Responsive Requirements

Breakpoints should prioritize content rather than device categories.

Required:

- large desktop
- desktop/laptop
- tablet
- mobile
- very small mobile ≤420px

The first viewport must maintain the source prompt's composition while adapting spacing and headline tracking.

Long scroll sections must recompose from multi-column layouts into single-column narrative layouts without simply shrinking desktop elements.

---

# 39. Performance Requirements

Prioritize fast first paint while retaining the hero video.

Requirements:

- lazy-load non-critical media
- avoid large image payloads
- defer non-essential JS
- keep third-party dependencies limited
- use a lightweight icon approach where possible
- avoid heavy animation frameworks
- do not use React just for UI components
- minimize layout shifts
- preconnect to required CDNs where appropriate

The background video should never block the text/UI from appearing.

---

# 40. SEO And Metadata

Each page needs:

- unique `<title>`
- unique meta description
- canonical URL where deployed
- Open Graph metadata
- Twitter/X metadata where relevant
- favicon
- semantic headings
- descriptive link text
- robots.txt
- sitemap.xml for production deployment

Suggested home title:

```text
BreachLabs — Build. Break. Verify. Fix.
```

Suggested description:

```text
BreachLabs is an autonomous AI application-security engineer that inspects, tests, investigates, verifies, explains, and retests software.
```

---

# 41. Flask Structure

Recommended isolated structure:

```text
website/
├── app.py
├── requirements.txt
├── .env.example
├── README.md
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── how-it-works.html
│   ├── architecture.html
│   ├── security.html
│   ├── capabilities.html
│   ├── demo.html
│   ├── about.html
│   ├── 404.html
│   ├── 500.html
│   └── components/
│       ├── nav.html
│       ├── button.html
│       ├── metric.html
│       ├── finding.html
│       ├── status.html
│       ├── architecture-node.html
│       └── footer.html
├── static/
│   ├── css/
│   │   ├── input.css
│   │   └── output.css
│   ├── js/
│   │   ├── main.js
│   │   ├── nav.js
│   │   ├── motion.js
│   │   ├── counters.js
│   │   ├── workflow.js
│   │   ├── architecture.js
│   │   └── demo.js
│   ├── images/
│   │   └── logo.webp
│   └── fonts/
│       └── GeistPixel-Circle.woff2
└── tests/
    ├── test_routes.py
    ├── test_security.py
    └── test_pages.py
```

The exact final file breakdown may be simplified, but the isolation principle must remain.

---

# 42. Component System

Build components around repeated meaning rather than generic UI abstractions.

Examples:

### `SectionLabel`

Small uppercase/monospace section identifier.

### `Metric`

Large value + suffix + label.

### `Status`

Detected / Investigating / Verified / Resolved.

### `EvidenceRow`

Source + evidence type + status.

### `WorkflowStage`

Stage number + stage title + active state + description.

### `ArchitectureNode`

System node + description + connection state.

### `TechnicalLog`

Small controlled stream of deterministic-looking product events.

These components should be visually specific to BreachLabs.

---

# 43. Demo Data Model

When using mocked data, represent it explicitly.

Example:

```json
{
  "assessment_id": "DEMO-0001",
  "status": "completed",
  "target": "breachlabs-demo",
  "duration_ms": 4820,
  "routes_discovered": 12,
  "findings": [
    {
      "id": "BL-DEMO-001",
      "title": "Example security finding",
      "severity": "high",
      "confidence": "verified",
      "status": "verified",
      "surface": "GET /api/example"
    }
  ]
}
```

No fake customer names or fake production claims should be inserted simply to make the interface look credible.

---

# 44. API Boundary

The first version can use local/mock data.

Future API endpoints may include:

```text
GET  /api/health
GET  /api/demo/assessment
GET  /api/demo/findings
GET  /api/demo/report
```

Future authenticated integration may expose:

```text
POST /api/assessments
GET  /api/assessments/<id>
GET  /api/assessments/<id>/events
GET  /api/assessments/<id>/findings
GET  /api/assessments/<id>/report
POST /api/assessments/<id>/retest
```

These future endpoints must not be implemented merely to satisfy the marketing-site PRD unless the underlying product safely supports them.

---

# 45. Error States

Create visually consistent:

- 404 page
- 500 page
- demo unavailable
- demo loading
- demo completed
- no findings
- assessment failed

The empty state should never look like a broken product.

Example empty state:

```text
NO VERIFIED FINDINGS

No issue has met the current evidence threshold.
This does not mean the application is guaranteed secure.
```

---

# 46. Testing And Verification

The implementation must be tested independently from the existing BreachLabs application.

## Route tests

Verify:

```text
/
/how-it-works
/architecture
/security
/capabilities
/demo
/about
```

## Browser tests

Verify:

- hero loads
- background video does not block UI
- navigation works
- mobile menu opens/closes correctly
- scroll animations trigger
- workflow stage changes
- architecture interaction works
- demo state changes work
- no visible console errors
- no broken assets

## Accessibility tests

Verify:

- keyboard navigation
- focus states
- menu ARIA state
- reduced motion
- heading hierarchy

## Isolation test

After implementation:

```text
git diff --name-only
```

must show website-only changes for the website task.

---

# 47. Acceptance Criteria

The website is accepted when:

### Product clarity

A first-time visitor understands what BreachLabs is and why it exists quickly.

### Visual continuity

The hero and all scroll sections feel like one coherent system.

### Motion quality

Animation communicates assessment progress and evidence rather than serving as decoration.

### Technical credibility

The site accurately explains:

- AI security investigation
- SAST
- DAST
- dependency checks
- secret detection
- browser automation
- MCP tools
- sandbox/isolation
- evidence collection
- verification
- remediation
- retesting

### Safety

The site does not create an unrestricted public attack surface.

### Responsive quality

The experience works on desktop, tablet, and mobile.

### Accessibility

Core content and navigation work without motion and without JavaScript-dependent interaction.

### Isolation

Existing BreachLabs project files are not changed.

### Maintainability

Templates, components, JS, and Tailwind styles are logically separated.

---

# 48. Recommended Implementation Phases

## Phase 1 — Foundation

Create `website/` with:

- Flask
- Jinja base template
- Tailwind setup
- asset structure
- global tokens
- typography
- responsive layout shell
- error pages

Do not modify the existing project.

## Phase 2 — Exact Hero

Implement the supplied MotionSites prompt as closely as possible.

Validate:

- video
- fonts
- header
- trust row
- headline
- subhead
- CTA
- metrics
- animations
- mobile menu

## Phase 3 — Scroll Narrative

Implement:

- product signal
- security loop
- repository → attack surface
- deterministic tools
- AI investigation
- verification
- evidence-backed finding
- fix/retest

## Phase 4 — Technical Depth

Implement:

- architecture
- MCP/tool boundaries
- security model
- capability explorer

## Phase 5 — Demo

Add safe deterministic demo experience using mock or controlled target data.

## Phase 6 — About + Final CTA

Add:

- about
- hackathon context
- roadmap
- final CTA
- footer

## Phase 7 — Polish

Tune:

- typography
- spacing
- motion
- responsive behavior
- hover/focus states
- section transitions
- video readability

## Phase 8 — QA

Run:

- Flask tests
- browser smoke tests
- accessibility checks
- responsive checks
- security checks
- isolation verification

---

# 49. Suggested Design Tokens

The following may be added without replacing the exact source variables:

```css
:root {
  --section-max: 1240px;
  --content-max: 1080px;
  --copy-max: 680px;
  --line: rgba(255, 255, 255, 0.10);
  --line-strong: rgba(255, 255, 255, 0.18);
  --surface-1: #050505;
  --surface-2: #0a0a0a;
  --surface-3: #111111;
  --accent: #ffffff;
  --success: #8bd3a7;
  --warning: #d6b66c;
  --danger: #e28d8d;
  --radius-sm: 10px;
  --radius-md: 16px;
  --radius-lg: 24px;
}
```

Keep the accent intentionally restrained.

---

# 50. Visual Details That Should Be Reused Across The Entire Site

The following details should become recognizable BreachLabs signatures:

### Three-dot active state

The hero navigation uses three dots. Reuse the three-dot language in section indicators and compact status navigation.

### Thin assessment line

Use a thin animated line as the thread connecting sections.

### Pixel display type

Use the retro display font for selected major statements and high-impact numerical signals, not every heading.

### Monospace evidence

Use monospace for technical artifacts.

### Dark environment

The site should feel like one instrument panel spanning a long editorial page, not a collection of isolated pages.

### White product artifacts

Use white/light surfaces sparingly for high-value artifacts such as a finding report preview or a mobile navigation sheet.

### Controlled glow

Use glow only to identify important interaction states, never as a constant decoration.

---

# 51. What The Website Should Communicate Without Saying It Directly

The visual language should imply:

```text
The system is watching.
The system is measuring.
The system is investigating.
The system is not guessing blindly.
The system can show evidence.
The system knows where its boundaries are.
```

This should emerge from the interaction design and information hierarchy rather than from exaggerated copy.

---

# 52. Agent Instructions

The AI coding agent implementing this PRD should follow this order:

1. Read the existing BreachLabs project only for context.
2. Create and work exclusively inside `website/`.
3. Preserve the source MotionSites hero requirements.
4. Establish the shared visual system before building every section.
5. Reuse components, tokens, motion primitives, and typography across pages.
6. Prefer one strong composition to multiple decorative cards.
7. Keep all claims factual and mark illustrative/demo content clearly.
8. Use shadcn/Magic UI interaction patterns without introducing React.
9. Keep JavaScript progressively enhanced.
10. Verify the website in a real browser after substantial visual changes.
11. Fix responsive and accessibility issues before adding more decoration.
12. Do not touch files outside `website/`.

The agent should be able to continue adding new sections later without changing the core design language.

---

# 53. Extensibility Rules

Any future page, feature, or section added to the site should satisfy all of these:

### Typography

Use the established Inter + display-font hierarchy.

### Layout

Use the established large-spacing, strong-grid, editorial composition.

### Motion

Use the existing reveal/easing language.

### Color

Use the neutral-first palette and restrained semantic colors.

### Interaction

Use the same shadcn/Magic UI-inspired behavior patterns.

### Content

Use evidence-oriented, technically precise language.

### Security

Never introduce arbitrary execution, public-target scanning, secret exposure, or misleading security guarantees.

### Accessibility

Every interaction must have a keyboard/semantic fallback.

---

# 54. Final Definition Of Done

The BreachLabs website is done when it feels like a single premium product experience from first pixel to final footer.

The visitor should be able to:

- understand BreachLabs immediately
- see the autonomous security-engineer concept
- follow the full security loop while scrolling
- understand how deterministic tooling and AI investigation work together
- see what evidence-backed verification looks like
- understand fix/retest behavior
- inspect the high-level architecture
- understand the security model and boundaries
- explore capabilities without a repetitive card grid
- experience a safe, deterministic demo where available
- reach the repository and relevant technical pages

Most importantly, the site should preserve the exact MotionSites hero language while extending it into a complete BreachLabs narrative.

The final product should feel:

> **less like a cybersecurity landing page and more like a security engineer working beside the developer.**

---

# Appendix A — Original MotionSites Reference Requirements To Preserve

The supplied prompt requires the implementation to retain the following exact details for the hero:

- `index.html`, `styles.css`, `main.js`, `assets/logo.webp`, `fonts/GeistPixel-Circle.woff2` reference structure
- exact CloudFront MP4 URL
- Inter Google Fonts source and weights 400/500/600
- BubbledotICG-FinePos OnlineWebFonts CDN
- Geist Pixel Circle local fallback
- Font Awesome 6.5.2 CDN and provided integrity hash
- exact CSS variables
- black background
- `100vh` / `100dvh`
- `overflow: hidden`
- absolute full-viewport cover video
- 3-region header/hero/stats composition
- exact logo dimensions/scaling behavior
- exact desktop nav shape and spacing
- exact Sign in styling
- header `slideDown`
- trust row sizing/overlap/inner-circle behavior
- exact headline wording and typography behavior
- exact subhead wording
- exact CTA wording and glow
- four exact metrics, with caution that the values must not be falsely presented as verified BreachLabs measurements
- `reveal`, `headlineFade`, and `revealPulse` behavior
- mobile burger/overlay/sheet behavior
- stats become 2 columns on mobile
- ≤420px headline/trust adjustments
- ≤700px height spacing adjustments
- reduced-motion support
- no headline gradient animation
- no full-bleed white trust disks
- no heavy logo/nav shadow
- no hero card grid

These requirements form the first viewport baseline. Everything after the first viewport should be designed as a continuation of that exact system.
