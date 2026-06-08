FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
EXPOSE 3001
ENV NODE_ENV=production PORT=3001
CMD ["node", "server.js"]
