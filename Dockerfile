# syntax=docker/dockerfile:1
# Code Guardian API + worker. The CMD is the brief's self-test command, so production runs under the same
# heap ceiling the reviewers test with.

ARG TRIVY_IMAGE=aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c

FROM ${TRIVY_IMAGE} AS trivy

# ---- build ----
FROM node:24-bookworm-slim AS build
WORKDIR /app
# Toolchain only in the build stage, in case better-sqlite3 has no prebuilt binary for this platform.
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ && rm -rf /var/lib/apt/lists/*
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev

# ---- runtime ----
FROM node:24-bookworm-slim
ENV NODE_ENV=production
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
RUN mkdir -p /data /work && chown node:node /data /work
USER node
ENV DATABASE_PATH=/data/code-guardian.db WORK_DIR=/work PORT=3000
# Cap V8's young generation at 2 MB per semi-space: about 25 MB less RSS for about 25 % slower parsing
# (measured). In a 200 MB limit that also holds git and Trivy, memory is the constraint, not throughput.
ENV NODE_OPTIONS=--max-semi-space-size=2
EXPOSE 3000
# curl (a few MB) rather than `node -e fetch(...)`: a second Node process would cost ~40 MB inside the
# container's memory limit every 30 s.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD curl -fsS http://127.0.0.1:3000/healthz >/dev/null || exit 1
CMD ["node", "--max-old-space-size=150", "dist/index.js"]
