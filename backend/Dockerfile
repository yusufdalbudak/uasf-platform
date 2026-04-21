FROM node:24-alpine
WORKDIR /app/backend
RUN apk update && apk add --no-cache nmap nmap-scripts
COPY package*.json ./
RUN npm install
COPY . .
CMD ["npx", "ts-node", "src/index.ts"]
