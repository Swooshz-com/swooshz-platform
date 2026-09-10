# syntax=docker/dockerfile:1

FROM node:22-bookworm-slim AS build

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src ./src
COPY scripts ./scripts

RUN npm run build
RUN npm prune --omit=dev

FROM node:22-bookworm-slim AS runtime

ENV NODE_ENV=production
ENV PLATFORM_HTTP_HOST=0.0.0.0
ENV PLATFORM_HTTP_PORT=3000

WORKDIR /app

COPY --from=build --chown=node:node /app/package.json /app/package-lock.json ./
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/dist ./dist
COPY --from=build --chown=node:node /app/scripts ./scripts

USER node

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 CMD node -e "const http = require('node:http'); const host = new URL(process.env.PLATFORM_PUBLIC_BASE_URL).host; const fail = () => { process.exitCode = 1; }; const request = http.get({ hostname: '127.0.0.1', port: process.env.PLATFORM_HTTP_PORT || '3000', path: '/healthz', headers: { Host: host } }, (response) => { response.resume(); response.on('error', fail); if (response.statusCode < 200 || response.statusCode >= 300) fail(); }); request.on('error', fail);"

CMD ["npm", "run", "platform:start"]
