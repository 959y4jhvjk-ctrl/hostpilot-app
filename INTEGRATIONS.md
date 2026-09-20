# Intégrations — état réel

| Fonction | Implémentée | Testée | Credentials | Validation externe | Statut |
|----------|-------------|--------|-------------|-------------------|--------|
| Stripe Checkout/Portal/Webhook HMAC | Oui | Structure + refus sans clés | STRIPE_* | Compte Stripe | CONFIG REQUISE sans clés |
| Email Resend/SendGrid | Oui (API réelle) | EMAIL_NOT_CONFIGURED sans clés | EMAIL_PROVIDER, EMAIL_API_KEY, EMAIL_FROM | Compte email | CONFIG REQUISE sans clés |
| IA rules+knowledge | Oui | Oui | optionnel AI_API_KEY | — | ACTIF local |
| Airbnb OAuth structure | Oui | Pas de credentials | AIRBNB_CLIENT_* | Partenariat Airbnb | CONFIG REQUISE |
| Booking.com | Structure | Idem | BOOKING_CLIENT_* | Partenariat | CONFIG REQUISE |
| Vrbo | Structure | Idem | VRBO_CLIENT_* | Partenariat | CONFIG REQUISE |

`POST /api/email/test` → 503 `EMAIL_NOT_CONFIGURED` si pas de clés ; 200 seulement si le provider confirme l’envoi.
