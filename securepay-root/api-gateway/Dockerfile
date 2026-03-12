FROM node:20-alpine

# Crear usuario no-root (Mínimo Privilegio)
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

# Copiar dependencias primero (cache de capas)
COPY package.json ./
RUN npm install --omit=dev

# Copiar código fuente
COPY src/server.js ./

# Cambiar propietario al usuario no-root
RUN chown -R appuser:appgroup /app
USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://localhost:8080/health || exit 1

CMD ["node", "server.js"]
