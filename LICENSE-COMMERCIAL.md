# Cadre commercial — HostPilot (code source)

Ce document est un **modèle** à adapter au contrat de vente signé entre vendeur et acheteur.

## Typiquement inclus dans une cession de code

- Code source de l’application HostPilot telle que livrée
- Documentation technique jointe (README, API, déploiement, etc.)
- Droit d’usage, modification et déploiement **pour l’acheteur** selon le contrat

## Typiquement non inclus

- Comptes et abonnements tiers (Stripe, Resend, SendGrid, cloud, domaine)
- Clés API, secrets, certificats
- Accès partenaires Airbnb / Booking.com / Vrbo / Expedia
- Marques et API des plateformes tierces (soumises à leurs conditions)
- Hébergement, maintenance, support continu (sauf clause contraire)
- Licence d’éléments tiers non redistribuables (à vérifier dans DEPENDENCIES.md)

## Responsabilités de l’acheteur

- Configurer les variables d’environnement
- Obtenir ses propres accès API et partenariats
- Vérifier la conformité légale (RGPD, hébergement, CGU plateformes) dans sa juridiction
- Ne pas présenter des intégrations non configurées comme « connectées »

## Disclaimer

Le logiciel est fourni « en l’état ». Aucune garantie de chiffre d’affaires, d’approbation par Airbnb/Booking/Vrbo, ou de disponibilité continue des APIs tierces.
