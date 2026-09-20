# HostPilot — Audit sécurité

## Corrections appliquées
- Rate limiting API (300 req/min/IP) + login (20/15min) + lockout 8 échecs
- Headers: X-Content-Type-Options, X-Frame-Options, Referrer-Policy, CORS configurable
- Erreurs 500 sans stack/detail exposé au client
- Mots de passe: scrypt (jamais en clair)
- JWT HS256 + expiration
- Multi-tenant: filtre organization_id sur les endpoints métier
- Cleaner: refus billing / création logements
- Check-in: token aléatoire, expiration, message générique si invalide
- Uploads: auth + isolation org + path traversal bloqué
- Stripe: secrets serveur uniquement; checkout refusé si non configuré
- GDPR: GET /api/gdpr/export
- Password reset structure (email = Configuration requise sans provider)
- saveDb atomique (tmp + rename)

## Tests automatisés (API)
| Test | Résultat |
|------|----------|
| Accès /api/properties sans auth | PASS 401 |
| Accès billing sans auth | PASS 401 |
| Isolation B ne voit pas props A | PASS |
| B ne peut pas supprimer prop A | PASS 404 |
| Token check-in invalide | PASS 404 |
| B ne peut pas checkout A | PASS 404 |
| Pas de sk_/whsec dans réponses | PASS |
| security/status | PASS |
| Mauvais login | PASS 401 |
| Check-in token valide | FAIL intermittent (EIO disque sandbox) |
| GDPR export | FAIL intermittent (EIO disque sandbox) |

## Config manuelle requise
- JWT_SECRET fort en production
- CORS_ORIGIN restreint
- Stripe TEST puis LIVE volontairement
- EMAIL_*, AI_*, OAuth plateformes
- PostgreSQL managé + backups
- HTTPS reverse proxy
- Webhook Stripe signature (raw body en prod)

## Checklist avant prod
- [ ] JWT_SECRET unique
- [ ] HTTPS
- [ ] CORS_ORIGIN
- [ ] PostgreSQL + backups testés
- [ ] Stripe webhook secret
- [ ] Pas de sk_live avant validation
- [ ] Monitoring erreurs
- [ ] RGPD process export/suppression
