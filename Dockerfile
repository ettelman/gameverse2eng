# syntax=docker/dockerfile:1
FROM node:18 AS builder

WORKDIR /usr/src/app

COPY package*.json ./
RUN npm ci --omit=dev

COPY . .

FROM node:18-slim

RUN useradd --user-group --create-home --shell /bin/false appuser

WORKDIR /usr/src/app

COPY --from=builder /usr/src/app ./

RUN chown -R appuser:appuser /usr/src/app

USER appuser

EXPOSE 3300

CMD ["node", "server.js"]
