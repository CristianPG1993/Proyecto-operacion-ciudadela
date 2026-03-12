'use strict';
require('dotenv').config();

const express        = require('express');
const helmet         = require('helmet');
const cors           = require('cors');
const morgan         = require('morgan');
const rateLimit      = require('express-rate-limit');
const jwt            = require('jsonwebtoken');
const { createProxyMiddleware } = require('http-proxy-middleware');

const app  = express();
const PORT = process.env.API_GATEWAY_PORT || 8080;

// =============================================
// SEGURIDAD: Cabeceras HTTP (Helmet)
// =============================================
app.use(helmet());
app.use(cors({ origin: process.env.ALLOWED_ORIGINS || '*' }));
app.use(morgan('combined'));
app.use(express.json({ limit: '10kb' })); // Limitar tamaño del cuerpo

// =============================================
// DISPONIBILIDAD: Rate Limiting (Anti-DDoS)
// =============================================
const globalLimiter = rateLimit({
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
    max:      parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
    standardHeaders: true,
    legacyHeaders:   false,
    message: { error: 'Demasiadas peticiones. Intenta de nuevo más tarde.' }
});

// Límite más estricto para rutas de autenticación (prevenir fuerza bruta)
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max:      10,
    message: { error: 'Demasiados intentos de autenticación. Intenta en 15 minutos.' }
});

app.use(globalLimiter);

// =============================================
// MIDDLEWARE: Verificación JWT
// =============================================
function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Token de autorización requerido.' });
    }

    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        // Inyectar datos del usuario en cabeceras hacia los servicios internos
        req.headers['x-user-id']   = String(decoded.userId);
        req.headers['x-user-role'] = decoded.role;
        req.headers['x-user-email']= decoded.email;
        next();
    } catch (err) {
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Token expirado.' });
        }
        return res.status(403).json({ error: 'Token inválido.' });
    }
}

// Middleware para requerir rol admin
function requireAdmin(req, res, next) {
    if (req.headers['x-user-role'] !== 'admin' && req.headers['x-user-role'] !== 'auditor') {
        return res.status(403).json({ error: 'Acceso denegado. Se requieren privilegios de administrador.' });
    }
    next();
}

// =============================================
// HEALTH CHECK del Gateway
// =============================================
app.get('/health', (req, res) => {
    res.json({
        service: 'api-gateway',
        status:  'ok',
        timestamp: new Date().toISOString()
    });
});

// =============================================
// PROXY: Auth Service (rutas públicas + limitadas)
// =============================================
app.use('/auth/login',    authLimiter);
app.use('/auth/register', authLimiter);

app.use('/auth', createProxyMiddleware({
    target:      process.env.AUTH_SERVICE_URL || 'http://auth-service:3001',
    changeOrigin: true,
    on: {
        error: (err, req, res) => {
            console.error('[GATEWAY] Error proxy auth-service:', err.message);
            res.status(502).json({ error: 'Servicio de autenticación no disponible.' });
        }
    }
}));

// =============================================
// PROXY: Transfer Service (rutas protegidas)
// =============================================
app.use('/transfer', verifyToken, createProxyMiddleware({
    target:      process.env.TRANSFER_SERVICE_URL || 'http://transfer-service:3002',
    changeOrigin: true,
    on: {
        error: (err, req, res) => {
            console.error('[GATEWAY] Error proxy transfer-service:', err.message);
            res.status(502).json({ error: 'Servicio de transferencias no disponible.' });
        }
    }
}));

// =============================================
// PROXY: Audit Logs Service (solo admin/auditor)
// =============================================
app.use('/audit', verifyToken, requireAdmin, createProxyMiddleware({
    target:      process.env.AUDIT_SERVICE_URL || 'http://audit-logs:3003',
    changeOrigin: true,
    on: {
        error: (err, req, res) => {
            console.error('[GATEWAY] Error proxy audit-service:', err.message);
            res.status(502).json({ error: 'Servicio de auditoría no disponible.' });
        }
    }
}));

// =============================================
// MANEJADOR 404 y errores globales
// =============================================
app.use((req, res) => {
    res.status(404).json({ error: 'Ruta no encontrada.' });
});

app.use((err, req, res, next) => {
    console.error('[GATEWAY] Error no manejado:', err.stack);
    res.status(500).json({ error: 'Error interno del servidor.' });
});

// =============================================
// INICIO DEL SERVIDOR
// =============================================
app.listen(PORT, () => {
    console.log(`[API-GATEWAY] Escuchando en puerto ${PORT}`);
    console.log(`[API-GATEWAY] Entorno: ${process.env.NODE_ENV || 'development'}`);
});
