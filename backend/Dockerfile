FROM node:22-bookworm-slim

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY . .

ENV NODE_ENV=production
USER node
EXPOSE 5000

CMD ["npm", "run", "start"]
