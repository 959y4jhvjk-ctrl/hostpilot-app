# HostPilot API

Base URL : `APP_URL` (ex. `https://votre-domaine.com`)  
Auth : header `Authorization: Bearer <jwt>` sauf routes publiques.

## Public

| Méthode | Path | Description |
|---------|------|-------------|
| GET | `/api/health` | Santé (pas de secrets) |
| POST | `/api/auth/register` | Inscription + org |
| POST | `/api/auth/login` | Connexion → token |
| POST | `/api/auth/forgot-password` | Demande reset (email si configuré) |
| POST | `/api/auth/reset-password` | `{ token, password }` |
| GET | `/api/checkin?token=` | Page données check-in |
| POST | `/api/checkin/confirm` | Confirmation voyageur |
| POST | `/api/webhooks/stripe` | Webhook (signature Stripe) |

## Authentifié

| Méthode | Path | Rôles |
|---------|------|-------|
| GET | `/api/auth/me` | tous |
| GET/POST | `/api/properties` | owner/admin/manager |
| DELETE | `/api/properties/:id` | owner/admin |
| GET/POST | `/api/reservations` | selon rôle |
| POST | `/api/reservations/:id/checkin-link` | |
| POST | `/api/reservations/:id/checkout` | idempotent → ménage |
| GET | `/api/cleaning` | + PATCH checklist, problem |
| GET/POST | `/api/incidents` | |
| GET | `/api/conversations` | messages, take control |
| GET/POST | `/api/automations` | |
| GET | `/api/notifications` | read-all, preferences |
| GET | `/api/dashboard` | stats serveur |
| GET | `/api/calendar` | |
| GET/POST | `/api/reviews/*` | analyse, approve response |
| GET/POST | `/api/pricing/*` | rules, recommendations |
| GET | `/api/integrations` | statut réel |
| POST | `/api/integrations/:platform/connect` | OAuth start |
| POST | `/api/integrations/:platform/sync` | **503 PARTNER_API_REQUIRED** sans API partenaire |
| POST | `/api/billing/create-checkout-session` | Stripe ou 503 |
| POST | `/api/email/test` | test envoi ou EMAIL_NOT_CONFIGURED |
| GET | `/api/gdpr/export` | export données user |

Erreurs courantes : `401` non auth · `403/404` multi-tenant · `503` configuration externe.

Exemples :

```bash
curl -s $APP_URL/api/health
curl -s -X POST $APP_URL/api/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"a@b.com","password":"password123"}'
```
