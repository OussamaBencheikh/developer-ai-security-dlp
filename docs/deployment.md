# Deployment

Local PostgreSQL is available through `infrastructure/docker/docker-compose.yml`. Production deployment must use managed secrets, TLS, HSTS, a restricted CORS origin, database backups, migrations, health checks, and a separate release process for the extension.

## Recovery baseline

Run the migration in `infrastructure/database/001_initial.sql` through a reviewed migration job. Take encrypted daily backups, retain a separate recovery copy, test a restore at least quarterly, and record the recovery point objective and recovery time objective before launch. Rotate `SESSION_SECRET`, database credentials, and payment-provider credentials through the secret manager; never put them in the repository.

Never commit `.env`, credentials, private keys, or payment-provider secrets.
