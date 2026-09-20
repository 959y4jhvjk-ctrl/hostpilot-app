# Dépendances et actifs tiers

## Runtime backend

| Élément | Version | Licence | Notes |
|---------|---------|---------|-------|
| Node.js | ≥ 18 | — | Runtime requis |
| Modules Node built-in (`http`, `fs`, `crypto`, `path`, `url`) | — | — | Aucun package npm obligatoire |

`package.json` n’impose **aucune** dépendance npm pour `npm start`.

## Frontend (CDN)

| Élément | Source | Notes commerciales |
|---------|--------|-------------------|
| Tailwind CSS | CDN (`cdn.tailwindcss.com`) | Vérifier conditions Tailwind / usage prod ; alternative self-host recommandée en prod |
| Polices / icônes | évent. via Tailwind / Unicode | Vérifier si ajouts futurs |

## APIs externes (optionnelles)

| Service | Usage | Compte acheteur requis |
|---------|-------|------------------------|
| Stripe | Abonnements SaaS | Oui |
| Resend / SendGrid | Email | Oui |
| OpenAI / xAI / autre | IA cloud optionnelle | Oui |
| Airbnb / Booking / Vrbo | OAuth + sync | **Partenariat officiel** |

## Code archivé

un ancien backend non livré — non utilisé, non supporté, fourni à titre historique uniquement.
