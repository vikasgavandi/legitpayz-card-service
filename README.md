# legitpayz-card-service (legitPayz)

Products, issuance, PIN set/verify, balance, upgrade/downgrade, block/unblock. (port `8002`). Part of the legitPayz credit-card microservices system.

## Run locally

Prereqs: Go 1.26+, Postgres (`cc/creditcard` migrated with `migrations/001_init.sql`), Redis.

```bash
PORT=8002 go run .
curl localhost:8002/health
```

## Docker

```bash
docker build -t legitpayz-card-service .
docker run -p 8002:8002 legitpayz-card-service
```

## Env

| Var | Purpose |
|-----|---------|
`DATABASE_URL` Postgres DSN · `REDIS_ADDR` Redis address
