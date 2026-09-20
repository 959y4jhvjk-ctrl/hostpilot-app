# HostPilot

**SaaS de gestion automatisée de locations courte durée** (code source pour reprise / déploiement).

Version **2.1.0** — backend Node.js unique, frontend SPA, persistance fichier JSON (migration PostgreSQL documentée comme étape suivante).

---

## Ce que contient ce produit

| Inclus | Non inclus |
|--------|------------|
| Code source backend + frontend | Comptes Stripe / email / plateformes |
| Documentation déploiement, API, sécurité | Clés API et secrets |
| Scripts de backup et tests smoke | Partenariats Airbnb / Booking / Vrbo |
| Architecture multi-tenant | Hébergement, domaine, certificats |
| Moteur d’automatisations serveur | Support illimité hors contrat de vente |

---

## Architecture

```
npm start  →  node src/api.js
                 ├─ GET /          → public/index.html
                 ├─ /api/*         → logique métier
                 └─ data/db.json   → source de vérité actuelle
```

- **Un seul backend :** `src/api.js` (ne pas lancer un ancien backend non livré)
- **Auth :** JWT + hash mot de passe
- **Isolation :** `organization_id` déterminé côté serveur
- **Jobs :** `setInterval` serveur (indépendant du navigateur)

Voir `ARCHITECTURE.md`.

---

## Prérequis

- Node.js **≥ 18**
- Aucune dépendance npm obligatoire pour démarrer (stdlib Node)

---

## Installation

```bash
cd hostpilot-saas
cp .env.example .env
# Éditer au minimum JWT_SECRET en production (≥ 32 caractères)
npm start
# → http://localhost:3001
```

Vérification :

```bash
npm run check    # syntaxe api.js
npm test         # smoke tests (serveur doit tourner)
curl http://localhost:3001/api/health
```

Base **propre** (optionnel) :

```bash
cp data/seed.empty.json data/db.json
```

---

## Variables d’environnement

Voir `.env.example`.

**Obligatoires en production :** `NODE_ENV=production`, `JWT_SECRET`, `APP_URL`, `CORS_ORIGIN`

**Recommandés :** `OAUTH_ENCRYPTION_KEY`, Stripe, Email

**Plateformes :** credentials uniquement après partenariat officiel — sinon statut `PARTNER_API_REQUIRED`

---

## Fonctionnalités

| Module | État |
|--------|------|
| Auth multi-utilisateur / multi-org | Opérationnel |
| Propriétés, réservations, calendrier, dashboard | Opérationnel |
| Check-in (token) / checkout → ménage idempotent | Opérationnel |
| Automatisations EVENT→ACTION | Opérationnel (serveur) |
| Messages + IA knowledge / escalade | Opérationnel (IA cloud optionnelle) |
| Avis, pricing (recommandations locales) | Opérationnel (pas de push plateforme simulé) |
| Stripe SaaS | Code prêt — clés requises |
| Email Resend/SendGrid | Code prêt — clés requises |
| Airbnb / Booking / Vrbo | Architecture OAuth — **partenariat requis** |

---

## Documentation

| Fichier | Contenu |
|---------|---------|
| `API.md` | Endpoints principaux |
| `DEPLOY.md` | Mise en production VPS |
| `BACKUP.md` | Sauvegardes / restauration |
| `INTEGRATIONS.md` | État réel des intégrations |
| `SECURITY_AUDIT.md` | Sécurité |
| `DATABASE.md` | Stockage + migration PG |
| `PRODUCT-STATUS.md` | Périmètre commercial |
| `LICENSE-COMMERCIAL.md` | Cadre de revente |
| `DEPENDENCIES.md` | Dépendances & licences |
| `CHANGELOG.md` | Historique |

---

## Licence / vente

Le cadre de cession du code est décrit dans `LICENSE-COMMERCIAL.md`.  
Les services tiers (Stripe, Airbnb, etc.) restent sous **leurs** conditions — non transférés avec le code.

---

## Support technique minimal

1. `GET /api/health`  
2. Logs console processus Node  
3. `data/db.json.bak` + `data/backups/`  
4. `npm test` contre une instance locale  
