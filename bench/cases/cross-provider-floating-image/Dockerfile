# DF-001: floating-tag base image. The build pulls whatever the
# upstream registry currently serves under ``node:20``; an
# upstream tag rewrite changes the build artifact silently.
FROM node:20

WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .

# DF-002: image runs as root by default (no USER directive).
CMD ["node", "server.js"]
