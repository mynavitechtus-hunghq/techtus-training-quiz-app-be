# Build stage
FROM node:22.16-alpine AS build-stage

RUN corepack enable

WORKDIR /app

COPY package.json .

COPY pnpm-lock.yaml .

RUN pnpm i --frozen-lockfile

COPY . .

RUN pnpm build


# Production stage
FROM node:22.16-alpine AS production-stage

RUN corepack enable

WORKDIR /app

COPY --from=build-stage /app/package.json .
COPY --from=build-stage /app/pnpm-lock.yaml .
COPY --from=build-stage /app/dist /app

RUN pnpm i --frozen-lockfile --only=production

EXPOSE 3000

VOLUME /app

CMD ["node", "/app/main.js"]