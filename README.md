# Acquisitions API - Docker & Neon Setup

This project is an Express/Node.js API that uses Neon as its Postgres backend and Drizzle ORM.
The repository is dockerized for both local development (with Neon Local) and production (with Neon Cloud).

## Prerequisites

- Docker and Docker Compose
- A Neon account with:
  - Neon API key
  - Neon project ID
  - At least one existing branch to use as the parent for ephemeral dev branches (for example, `main`)

## Environment files

Two environment files are used to clearly separate development and production configuration:

- `.env.development` — used by `docker-compose.dev.yml`
- `.env.production` — used by `docker-compose.prod.yml`

### .env.development

Key values to set:

- `NEON_API_KEY` — your Neon API key
- `NEON_PROJECT_ID` — your Neon project ID
- `PARENT_BRANCH_ID` — the branch ID Neon Local will clone for each ephemeral dev branch
- `DATABASE_URL` — Postgres URL that points to Neon Local inside the Docker network

The default value configured is:

```bash path=null start=null
DATABASE_URL=postgres://neon:npg@neon-local:5432/acquisitions?sslmode=require
```

This matches the recommended Neon Local connection string. Inside the Compose network, the Neon Local host is `neon-local`.

### .env.production

Set `DATABASE_URL` to the Neon Cloud connection string from the Neon console, for example:

```bash path=null start=null
DATABASE_URL=postgres://user:password@your-project-id.region.neon.tech/dbname?sslmode=require
```

No Neon Local variables are needed in production.

## How the database connection works

The app uses `@neondatabase/serverless` with Drizzle ORM, configured in `src/config/database.js`.

- In **development**, `docker-compose.dev.yml` sets `NEON_LOCAL_MODE=true` and
  `NEON_LOCAL_FETCH_ENDPOINT=http://neon-local:5432/sql`.
  The app then routes all database traffic through the Neon Local proxy container.
- In **production**, `NEON_LOCAL_MODE` is not set, so the Neon driver talks directly
  to the Neon Cloud endpoint from `DATABASE_URL`.

Environment-based switching is handled transparently in code; you only need to set `DATABASE_URL`
correctly for each environment.

## Local development with Neon Local

1. Fill in `.env.development` with your Neon credentials and desired database name.
2. Start the dev stack:

   ```bash path=null start=null
   docker compose -f docker-compose.dev.yml up --build
   ```

3. The API will be available at `http://localhost:3000`.
4. The Neon Local container will:
   - Use `NEON_API_KEY`, `NEON_PROJECT_ID`, and `PARENT_BRANCH_ID`.
   - Create an **ephemeral branch** when the container starts.
   - Delete that branch when the container stops, giving you a clean database per run.

### Running migrations against Neon Local

To run Drizzle migrations against the ephemeral Neon Local branch from inside the dev stack:

```bash path=null start=null
docker compose -f docker-compose.dev.yml run --rm app npm run db:migrate
```

This uses the same `DATABASE_URL` and environment as the running application.

## Production deployment with Neon Cloud

1. Fill in `.env.production` with your production settings, especially:

   - `NODE_ENV=production`
   - `DATABASE_URL` pointing to your Neon Cloud database URL

2. Build and run the production stack:

   ```bash path=null start=null
   docker compose -f docker-compose.prod.yml up --build -d
   ```

3. The app container will:

   - Run `npm run start` using the image built from `Dockerfile`.
   - Connect **directly** to Neon Cloud using the `DATABASE_URL` you provided.
   - Not start any Neon Local proxy container.

## Switching between dev and prod

- **Development**: `docker compose -f docker-compose.dev.yml up --build`
  - Uses `.env.development`
  - Starts both `neon-local` and `app` services
  - `DATABASE_URL` points at Neon Local in the compose network
- **Production**: `docker compose -f docker-compose.prod.yml up --build -d`
  - Uses `.env.production`
  - Starts only the `app` service
  - `DATABASE_URL` points at your Neon Cloud database

By changing only the compose file and env file, the same application image runs
in both environments while using the correct Neon backend.