# PRODUCT-STATUS (honnête — audit vendeur)

## 🟢 Fonctionnel
Auth multi-org, propriétés, réservations, calendrier, dashboard, check-in token, checkout → ménage **idempotent**, cleaning, incidents, automatisations serveur, messagerie + knowledge, avis/pricing **locaux**, notifications, GDPR export, health, backups, smoke tests.

## 🟠 Dépendances externes
| Besoin | Détail |
|--------|--------|
| JWT_SECRET, HTTPS, CORS, APP_URL | Déploiement |
| OAUTH_ENCRYPTION_KEY | Avant OAuth |
| Stripe | Monétisation |
| Resend/SendGrid | Emails |
| Partenariat Airbnb/Booking/Vrbo | Sync réelle — sinon `PARTNER_API_REQUIRED` |
| AI_API_KEY | IA cloud optionnelle |

## 🔴 Problèmes connus (non bloquants reprise)
- Stockage JSON mono-processus
- CSS Tailwind CDN
- Fichier `api.js` monolithique
- Intégrations plateformes non opérationnelles sans partenariat (documenté)

## Non inclus dans la vente
Comptes, clés, hébergement, partenariats plateformes, support illimité.
