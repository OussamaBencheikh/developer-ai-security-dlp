# Deployment

Local PostgreSQL is available through `infrastructure/docker/docker-compose.yml`. Production deployment must use managed secrets, TLS, HSTS, a restricted CORS origin, database backups, migrations, health checks, and a separate release process for the extension.

Never commit `.env`, credentials, private keys, or payment-provider secrets.
