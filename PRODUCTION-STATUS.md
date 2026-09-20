# PRODUCTION-STATUS — HostPilot

## 🟢 FONCTIONNEL ET TESTÉ
- Auth JWT, multi-tenant, propriétés, réservations
- Check-in / checkout idempotent → 1 ménage
- Automatisations serveur, IA knowledge, notifications
- Email : `EMAIL_NOT_CONFIGURED` sans clés ; envoi réel Resend/SendGrid si configuré
- Stripe : webhook HMAC ; pas de faux paiement
- Sync plateformes : **HTTP 503 `PARTNER_API_REQUIRED`** (plus de 200 ok + synced:0)
- Tokens OAuth : **AES-256-GCM** si `OAUTH_ENCRYPTION_KEY` ; refus stockage sinon
- Backend unique `src/api.js` ; stubs archivés

## 🟠 CONFIGURATION EXTERNE
| Élément | Action propriétaire HostPilot |
|---------|------------------------------|
| JWT_SECRET | ≥32 car. aléatoires |
| HTTPS + domaine | APP_URL, CORS_ORIGIN |
| OAUTH_ENCRYPTION_KEY | Requis avant toute connexion OAuth prod |
| Stripe | Compte + clés TEST/LIVE + webhook |
| Email | Resend ou SendGrid + EMAIL_* |
| Airbnb | **Partenariat API officiel** + CLIENT_ID/SECRET |
| Booking.com | **Compte développeur/partenaire** + credentials |
| Vrbo/Expedia | **Partenariat Expedia Group** + credentials |
| PostgreSQL | `POSTGRESQL_MIGRATION_REQUIRED` (étape ultérieure) |

## 🔴 BLOQUANT TECHNIQUE
- Aucun pour self-host configuré
- SaaS multi-nœuds : migrer hors `db.json` (POSTGRESQL_MIGRATION_REQUIRED)

## Décision PostgreSQL
**Migration non démarrée** (éviter double source de vérité). JSON conservé + backups.

## Actions pour SaaS publique
1. Domaine + HTTPS + reverse proxy  
2. `.env` production (JWT, CORS, APP_URL, OAUTH_ENCRYPTION_KEY)  
3. Stripe TEST puis LIVE  
4. Email provider  
5. Demander accès API partenaires Airbnb / Booking / Vrbo  
6. Planifier migration PostgreSQL  
7. Monitoring + backups off-site  

## VERDICT
**PRÊT APRÈS CONFIGURATION**
