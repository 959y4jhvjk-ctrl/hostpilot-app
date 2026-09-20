# Base de données

## Actuel
**Fichier** `data/db.json` — source de vérité unique.

- Écritures : fichier temporaire + rename + `.bak`
- Backups horodatés : `data/backups/` + `scripts/backup-db.sh`
- Seed propre : `data/seed.empty.json`

## Limite
Une instance Node à la fois. Pas de multi-écrivain.

## Évolution
`POSTGRESQL_MIGRATION_REQUIRED` pour un SaaS multi-nœuds.  
**Pas de migration partielle livrée** (évite double source de vérité).
