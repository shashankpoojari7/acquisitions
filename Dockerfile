# Base image with Node.js 22 (LTS)
FROM node:22-alpine

# Install build tools for native dependencies like bcrypt
RUN apk add --no-cache python3 make g++

WORKDIR /usr/src/app

# Install dependencies first for better layer caching
COPY package.json ./
# If you add a lockfile later (package-lock.json, pnpm-lock.yaml, yarn.lock),
# copy it here as well to get reproducible installs.
RUN npm install

# Copy the rest of the application source
COPY . .

# Default runtime configuration (can be overridden via environment variables)
ENV NODE_ENV=production \
    PORT=3000

EXPOSE 3000

CMD ["npm", "run", "start"]