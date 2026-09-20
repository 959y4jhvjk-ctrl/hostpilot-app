# HANDOVER — Reprise HostPilot par un développeur

## 1. Architecture
- Backend unique : `src/api.js` (Node HTTP, zéro dépendance npm obligatoire)
- Frontend : `public/index.html` (+ `checkin.html`)
- Données : `data/db.json` (une seule source de vérité)
- **Ne pas** démarrer un ancien backend non livré

## 2. Installation
```bash
cd hostpilot-saas
cp .env.example .env
# Production: NODE_ENV=production JWT_SECRET=<32+ chars> APP_URL=https://… CORS_ORIGIN=https://…
npm start
```

## 3. Variables `.env`
Voir `.env.example`. Obligatoire prod : `JWT_SECRET`, `APP_URL`, `CORS_ORIGIN`.  
OAuth plateformes : `OAUTH_ENCRYPTION_KEY` avant toute connexion.

## 4. Lancement / tests
```bash
npm run check
npm start          # terminal 1
npm test           # terminal 2 — smoke tests
curl localhost:3001/api/health
```

## 5. Base de données
Fichier JSON atomique + `.bak` + `data/backups/` (rotation).  
Base propre : `cp data/seed.empty.json data/db.json`  
PostgreSQL : **non branché** — évolution future (`DATABASE.md`).

## 6. API
`API.md` + `openapi.yaml`. Auth Bearer JWT.

## 7. Auth
Register crée user + organisation. JWT en localStorage côté client (`hp_token`). Rôles : owner, admin, manager, cleaner, staff.

## 8. Jobs
`setInterval` dans `api.js` : automatisations + file email. Indépendant du navigateur.

## 9. Intégrations
`INTEGRATIONS.md`. Sync plateformes → `PARTNER_API_REQUIRED` sans partenariat API officiel. Pas de scraping.

## 10. Stripe
Secrets serveur uniquement. Webhook HMAC si `STRIPE_WEBHOOK_SECRET`. Sans clés → 503.

## 11. Email
`EMAIL_PROVIDER=resend|sendgrid` + clé + from. `POST /api/email/test`. Sinon `EMAIL_NOT_CONFIGURED`.

## 12. IA
Knowledge logement + règles sans clé. Cloud optionnel (`AI_API_KEY`).

## 13. Backups
`npm run backup` ou `./scripts/backup-db.sh` — voir `BACKUP.md`.

## 14. Déploiement
`DEPLOY.md` — VPS, reverse proxy HTTPS, pm2, cron backup.

## 15. Problèmes connus / limitations
- JSON mono-instance (pas multi-nœuds)
- Tailwind via CDN (self-host recommandé en prod stricte)
- Airbnb/Booking/Vrbo : partenariat externe requis
- Monolithe `api.js` (~4k lignes) — lisible, à modulariser plus tard

## 16. Prochaines étapes recommandées
1. PostgreSQL + pool  
2. Self-host CSS  
3. Suite de tests élargie  
4. Demandes partenaires plateformes  

## Check-in (sécurité)
- Token renvoyé **une fois** à la génération ; stocké en **SHA-256** uniquement.
- Page publique : `checkin.html?token=` + `GET /api/checkin`.
- XSS : rendu via textContent / DOM (pas innerHTML de données API).
