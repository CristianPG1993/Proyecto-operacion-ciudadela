FROM postgres:16-alpine

# Variables de entorno por defecto (sobreescribibles desde docker-compose)
ENV POSTGRES_DB=securepay_db
ENV POSTGRES_USER=securepay_admin
ENV POSTGRES_PASSWORD=SecurePay_Admin_P@ss_2024!

# Copiar el script de inicialización
# PostgreSQL ejecuta automáticamente los .sql de este directorio al arrancar
COPY init.sql /docker-entrypoint-initdb.d/init.sql

EXPOSE 5432
