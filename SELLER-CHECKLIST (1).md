# Checklist vendeur HostPilot

## Code
- [x] Backend unique `src/api.js`
- [x] `npm start` → api.js
- [x] Pas de secrets dans le dépôt
- [x] Version 2.1.2+

## Sécurité
- [x] JWT (refus secret faible en production)
- [x] Multi-tenant (smoke)
- [x] Check-in tokens hashés (SHA-256)
- [x] checkin.html sans XSS (textContent/DOM)
- [x] OAuth AES-GCM si `OAUTH_ENCRYPTION_KEY`
- [x] Webhook Stripe signé si secret configuré

## Données livrées
- [x] `data/db.json` = copie de `seed.empty.json` (0 utilisateur)
- [x] Pas de `@test.local` / comptes de smoke dans le ZIP
- [x] `.gitignore` ignore `.env`, `db.json`, backups, logs

## Documentation
- [x] README, HANDOVER, API, DEPLOY, PRODUCT-STATUS, DEPENDENCIES

## Tests
- [x] `npm run check`
- [x] `npm test` (crée ses propres données temporaires)
