# Break-it service. Build context: the repository root.
#   docker build -f apps/break-it/Dockerfile -t zkif-break-it .
# On Railway, set the service variable RAILWAY_DOCKERFILE_PATH=apps/break-it/Dockerfile.
FROM node:26.13.1-bookworm-slim

ENV BREAKIT_CRS_PATH=/app/crs
RUN npm install -g pnpm@12.18.0

WORKDIR /app
COPY . .
RUN pnpm install --frozen-lockfile --filter "@zk-intent-firewall/break-it..." \
 && pnpm --filter @zk-intent-firewall/mcp-firewall run build

# NODE_ENV is set only after the install: with it, pnpm would skip the TypeScript compiler the
# firewall's build needs.
ENV NODE_ENV=production

# Download Barretenberg's reference string now, at build time: at run time the engine has no
# network and fails closed without it.
RUN mkdir -p /app/crs && cd apps/break-it && node scripts/warm-crs.ts

# Run as an unprivileged user. The attempt log goes to BREAKIT_DATA_DIR (a Railway volume); Railway
# mounts volumes as root, so set RAILWAY_RUN_UID=0 there, or the log stays in memory only.
RUN chown -R node:node /app/crs
USER node
WORKDIR /app/apps/break-it
EXPOSE 8080
CMD ["node", "src/front/main.ts"]
