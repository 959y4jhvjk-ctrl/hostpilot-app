# Déploiement HostPilot (VPS)

1. **Serveur** Ubuntu 22.04+ ou équivalent, firewall ouvert 80/443  
2. **Node.js 18+** (`node -v`)  
3. Copier le projet, `cp .env.example .env`  
4. Renseigner : `NODE_ENV=production`, `JWT_SECRET` (≥32), `APP_URL=https://…`, `CORS_ORIGIN=https://…`, `OAUTH_ENCRYPTION_KEY`  
5. `npm start` ou **pm2** : `pm2 start src/api.js --name hostpilot`  
6. **Caddy/Nginx** : reverse proxy HTTPS → `127.0.0.1:3001`  
7. Stripe webhook : `https://domaine/api/webhooks/stripe`  
8. Cron : `0 * * * * /path/hostpilot-saas/scripts/backup-db.sh`  
9. Monitoring : uptime sur `/api/health`  
10. Restauration : `BACKUP.md`  
11. Mise à jour : arrêter process, remplacer fichiers, redémarrer (garder `data/` et `.env`)  

Ne jamais exposer `data/db.json` ni `.env` en téléchargement public.
