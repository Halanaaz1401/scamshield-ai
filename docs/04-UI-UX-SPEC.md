# UI/UX Specification

## Design objective

Create a premium, trustworthy, modern cybersecurity SaaS interface
inspired by the supplied CodeAnt security/pentesting reference and the
supplied 21st.dev/React Bits wireframe-template screenshots.

The references are inspiration only. Do not reproduce their branding,
copy, proprietary assets or pixel-identical layouts.

## Visual language

-   Dark-first
-   Near-black background
-   High-contrast typography
-   Large editorial headings
-   Thin low-contrast borders
-   Restrained rounded containers
-   Generous whitespace
-   One controlled accent color
-   Semantic risk colors
-   No large white footer
-   No generic hacker/matrix aesthetic

## Screens

### 1. Landing / Analyzer

Large headline, concise explanation, prominent message input/action and
an original animated security visual.

### 2. Analysis

Full-width focused state with subtle scanning/progress motion. Do not
claim backend work that did not occur.

### 3. Result

Strong hierarchy: risk score/level, scam category, indicators,
explanation, protective actions.

### 4. Final CTA

Large editorial CTA with an original animated side visual. Suggested
direction: "Pause before you trust."

### 5. Footer

Dark footer with brand, product/resources/security links and appropriate
attribution.

## Motion

Use smooth load reveals, staggered typography, scroll-triggered
fades/translations, button transitions and result reveal. Respect
reduced-motion preferences. Motion must not block interaction.

## Responsive

Desktop: strong two-column compositions. Tablet: reduce spacing/stack
complex areas. Mobile: single-column, touch-friendly, input-first,
stacked result, reduced decoration.

## Components

Navbar, Button, MessageInput, AnalysisProgress, RiskBadge, RiskScore,
ScamCategory, IndicatorList, RecommendationList, ResultPanel,
AnimatedSecurityVisual, SectionHeader, Footer.

## Core UX

**Paste → Analyze → Understand → Protect**
