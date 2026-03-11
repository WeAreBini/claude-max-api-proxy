FROM node:20-bookworm-slim AS build

WORKDIR /app

COPY package.json package-lock.json tsconfig.json ./
RUN npm ci

COPY src ./src
RUN npm run build

FROM node:20-bookworm-slim

ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=3456

RUN npm install -g @anthropic-ai/claude-code \
  && mkdir -p /root/.config/claude

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev \
  && npm cache clean --force

COPY --from=build /app/dist ./dist
COPY README.md LICENSE ./

EXPOSE 3456

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:' + (process.env.PORT || '3456') + '/health').then((response) => process.exit(response.ok ? 0 : 1)).catch(() => process.exit(1))"

CMD ["node", "dist/server/standalone.js"]