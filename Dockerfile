# ======== Byggsteg ========
FROM node:18 AS builder

WORKDIR /usr/src/app

COPY package*.json ./
RUN npm ci --omit=dev

COPY . .

# ======== Produktionssteg ========
FROM node:18-slim

# Skapa en app-användare (ej root) för bättre säkerhet
RUN useradd --user-group --create-home --shell /bin/false appuser

WORKDIR /usr/src/app

# Kopiera från builder-steget (node_modules och all kod)
COPY --from=builder /usr/src/app ./

# Om du vill skapa en tom db-fil med rätt rättigheter direkt i containern:
# RUN touch gameverse.db && chown appuser:appuser gameverse.db

# Ändra ägare till appuser (inklusive ev. databasen)
RUN chown -R appuser:appuser /usr/src/app

USER appuser

EXPOSE 3300

CMD ["node", "server.js"]
