# CoreCheck Control Plane — lean staging/prod image (Fly / Render / Docker)
# Build context: corecheck-api/
FROM node:20-alpine AS build
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json index.ts ./
COPY src ./src
COPY public ./public
RUN npm run build

FROM node:20-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production

COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY --from=build /app/dist ./dist
COPY --from=build /app/public ./public

EXPOSE 3000
USER node
CMD ["node", "dist/index.js"]
