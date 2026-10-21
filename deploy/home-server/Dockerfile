FROM node:24-bookworm-slim AS build
WORKDIR /app
COPY . .
RUN npm ci && npm run build && npm test && npm run typecheck && npm run build -w apps/web -- --base=/soc-watch/ && cp apps/extension/src/icon-128.svg apps/web/dist/bridge-icon.svg
FROM node:24-bookworm-slim
WORKDIR /app
COPY --from=build --chown=node:node /app /app
RUN mkdir -p /app/state && chown node:node /app/state
COPY --chmod=644 deploy/home-server/backup.mjs /opt/backup.mjs
USER node
EXPOSE 8080
CMD ["sh", "-c", "node /opt/backup.mjs && exec node scripts/serve-web.mjs"]
