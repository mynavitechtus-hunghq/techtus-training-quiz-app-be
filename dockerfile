# Base
FROM node:22.16-alpine AS development-stage

RUN corepack enable

WORKDIR /app

COPY package.json .

COPY pnpm-lock.yaml .

RUN pnpm i --frozen-lockfile

COPY . .


# Build stage
FROM node:22.16-alpine AS build-stage

RUN corepack enable

WORKDIR /app

COPY package.json .

COPY pnpm-lock.yaml .

COPY --from=development-stage /app/node_modules ./node_modules

COPY . .

RUN pnpm build


# Production stage
FROM node:22.16-alpine AS production-stage

RUN corepack enable

WORKDIR /app

COPY --from=build-stage /app/package.json .
COPY --from=build-stage /app/pnpm-lock.yaml .
COPY --from=build-stage /app/dist ./dist

RUN pnpm i --frozen-lockfile --only=production

EXPOSE 3000

VOLUME /app

CMD ["node", "dist/main.js"]