FROM node:20-alpine

# Herramientas necesarias para compilar bcrypt (módulo nativo)
RUN apk add --no-cache python3 make g++

RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev

COPY server.js ./

RUN chown -R appuser:appgroup /app
USER appuser

EXPOSE 3001

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD wget -qO- http://localhost:3001/auth/health || exit 1

CMD ["node", "server.js"]
