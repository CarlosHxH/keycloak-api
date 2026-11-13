FROM node:22.13.0-alpine

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY . .

ENV PORT=9090
EXPOSE 9090

CMD ["node", "server.js"]
