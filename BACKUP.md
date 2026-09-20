# Sauvegardes HostPilot (`data/db.json`)

## Emplacements

| Fichier | Rôle |
|---------|------|
| `data/db.json` | Base active |
| `data/db.json.bak` | Dernier snapshot (écrit à chaque `saveDb`) |
| `data/backups/db-YYYYMMDDTHHMMSSZ.json` | Historique (script) |

Les secrets d’environnement (JWT, Stripe…) **ne sont pas** dans `db.json`.

## Créer un backup

```bash
./scripts/backup-db.sh
```

Conserve les 14 dernières copies dans `data/backups/`.

**Production :** cron quotidien ou horaire :

```cron
0 * * * * /path/to/hostpilot-saas/scripts/backup-db.sh
```

## Restaurer

1. Arrêter le serveur HostPilot  
2. `cp data/backups/db-XXXX.json data/db.json`  
3. Redémarrer `node src/api.js`  
4. Vérifier login + données

En cas de corruption, essayer d’abord `data/db.json.bak`.

## Fréquence recommandée

- Self-host léger : 1× / jour  
- Usage intensif : 1× / heure + copie off-site (S3, autre disque)
