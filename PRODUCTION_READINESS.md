# Production readiness — HostPilot

## Fonctionnel (vérifié API)
- [x] Auth register/login/me + 401 non authentifié
- [x] Multi-tenant isolation propriétés / checkout
- [x] Réservation → check-in token → confirm → checkout → ménage
- [x] Messagerie IA (checkout) + escalade remboursement
- [x] Pricing recommandation + apply (HostPilot only)
- [x] Avis analyse + réponse + envoi plateforme = Config requise
- [x] Dashboard / calendar / system status
- [x] Billing sans clés = Configuration requise
- [x] Onboarding status
- [x] GDPR export
- [x] Export CSV réservations
- [x] Rate limit + headers sécurité

## À configurer (externe)
- [ ] PostgreSQL + migrations + backups testés
- [ ] JWT_SECRET production
- [ ] HTTPS / reverse proxy
- [ ] Stripe TEST puis LIVE volontaire
- [ ] Email provider
- [ ] AI provider (optionnel — rules fonctionnent sans)
- [ ] OAuth Airbnb / Booking / Vrbo
- [ ] Monitoring (Sentry etc.)
- [ ] CORS_ORIGIN strict

## Bloquant pour prod réelle
1. Stockage JSON fichier ≠ PostgreSQL haute dispo
2. Secrets et HTTPS non fournis dans cet environnement
3. Intégrations plateformes non branchées (partenariats API)
4. EIO disque intermittent possible sous charge sandbox

## Verdict
Techniquement **cohérent et testable en self-host**.
**Pas « production cloud ready »** tant que PostgreSQL, HTTPS, secrets et backups ne sont pas en place.
