# Architecture HostPilot — backend unique

## Canonique (production / dev)

```
npm start  →  node src/api.js
                ├─ HTTP API /api/*
                ├─ Static public/
                └─ data/db.json
```

**Un seul backend :** `src/api.js`  
**Pas de SQLite runtime, pas d’Express concurrent.**

## Archivé (ne pas utiliser)

un ancien backend non livré — ancienne ébauche Express/SQLite/Prisma, **incomplète**.

## Frontend

`public/index.html` (également copié en `HostPilot-Tout-En-Un.html`)
