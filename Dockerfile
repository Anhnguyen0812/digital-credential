FROM node:24-alpine
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --no-audit --no-fund
COPY tsconfig.json vitest.config.ts ./
COPY src ./src
COPY public ./public
COPY test-vectors ./test-vectors
ENV NODE_ENV=production
USER node
# Lenh khoi chay duoc chon boi docker-compose (command: npm run start:issuer | start:verifier | start:wallet)
CMD ["npm", "run", "start:wallet"]
