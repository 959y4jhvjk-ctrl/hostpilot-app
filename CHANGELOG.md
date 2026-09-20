# Changelog HostPilot

## 2.1.0 — Package commercial

- Documentation acheteur (API, OpenAPI, LICENSE-COMMERCIAL, DEPENDENCIES, PRODUCT-STATUS)
- Smoke tests `npm test`
- Seed vide `data/seed.empty.json`
- Email Resend/SendGrid réel (pas de faux « envoyé »)
- Sync plateformes → `PARTNER_API_REQUIRED` (HTTP 503)
- Tokens OAuth chiffrés AES-256-GCM (`OAUTH_ENCRYPTION_KEY`)
- JWT_SECRET refusé s’il est faible en production
- Backups auto + script
- Backend unique `src/api.js`

## 2.0.0 — Cœur SaaS

- Multi-tenant, réservations, check-in/out, ménage, automatisations, dashboard, avis, pricing

## 2.1.1 — Audit vendeur

- Base livrée vide (seed)
- HANDOVER.md + SELLER-CHECKLIST.md
- PRODUCT-STATUS / DATABASE clarifiés pour acheteur technique

## 2.1.2 — Audit vendeur check-in / XSS / livrable
- Tokens check-in hashés (plus de plaintext persisté)
- Routes legacy unifiées
- checkin.html sans XSS innerHTML
- app.js archivé (SPA = index.html uniquement)
- .gitignore professionnel
