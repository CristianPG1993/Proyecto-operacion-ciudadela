'use strict';
require('dotenv').config();

const express  = require('express');
const helmet   = require('helmet');
const cors     = require('cors');
const { Pool } = require('pg');

const app  = express();
const PORT = process.env.AUDIT_SERVICE_PORT || 3003;

// =============================================
// SEGURIDAD
// =============================================
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10kb' }));

// =============================================
// CONEXIÓN A BASE DE DATOS (Mínimo Privilegio)
// Usa usuario audit_svc: solo INSERT y SELECT en audit_logs
// =============================================
const pool = new Pool({
    host:     process.env.DB_HOST     || 'postgres',
    port:     parseInt(process.env.DB_PORT) || 5432,
    database: process.env.POSTGRES_DB || 'securepay_db',
    user:     'audit_svc',
    password: 'Audit_Svc_P@ss_2024!',
    max:      10,
    idleTimeoutMillis: 30000
});

pool.connect()
    .then(client => {
        console.log('[AUDIT-SERVICE] Conectado a PostgreSQL');
        client.release();
    })
    .catch(err => console.error('[AUDIT-SERVICE] Error DB:', err.message));

// =============================================
// MIDDLEWARE: Solo acceso desde la red interna Docker
// Los logs NO son modificables ni eliminables (inmutabilidad)
// =============================================
function internalOnly(req, res, next) {
    // En producción real: verificar que la IP sea de la red interna de Docker
    // Aquí verificamos que venga del gateway con cabecera especial
    const internalHeader = req.headers['x-internal-service'];
    if (!internalHeader) {
        // También permitir si el rol es admin (viene del gateway)
        const userRole = req.headers['x-user-role'];
        if (req.method === 'POST' || (req.method === 'GET' && (userRole === 'admin' || userRole === 'auditor'))) {
            return next();
        }
        return res.status(403).json({ error: 'Acceso restringido a servicios internos.' });
    }
    next();
}

// =============================================
// RUTAS
// =============================================

// Health check
app.get('/audit/health', (req, res) => {
    res.json({ service: 'audit-logs', status: 'ok', timestamp: new Date().toISOString() });
});

// ── POST /audit/log ──────────────────────────
// Recibe eventos de otros microservicios (solo escritura)
app.post('/audit/log', internalOnly, async (req, res) => {
    const {
        userId,
        action,
        resource,
        ipAddress,
        userAgent,
        details,
        severity = 'INFO'
    } = req.body;

    // Validaciones básicas
    if (!action || typeof action !== 'string' || action.length > 100) {
        return res.status(400).json({ error: 'Campo "action" requerido y máximo 100 caracteres.' });
    }

    const validSeverities = ['INFO', 'WARNING', 'ERROR', 'CRITICAL'];
    const safeSeverity = validSeverities.includes(severity) ? severity : 'INFO';

    try {
        // Consulta parametrizada (Anti-SQLi)
        const result = await pool.query(
            `INSERT INTO audit_logs (user_id, action, resource, ip_address, user_agent, details, severity)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             RETURNING id, created_at`,
            [
                userId     || null,
                action,
                resource   || null,
                ipAddress  || null,
                userAgent  || null,
                details    ? JSON.stringify(details) : null,
                safeSeverity
            ]
        );

        // Si es crítico, loguear también en consola
        if (safeSeverity === 'CRITICAL' || safeSeverity === 'ERROR') {
            console.error(`[AUDIT] ${safeSeverity} | user=${userId} | action=${action} | ip=${ipAddress}`);
        }

        res.status(201).json({ logId: result.rows[0].id, timestamp: result.rows[0].created_at });

    } catch (err) {
        console.error('[AUDIT] Error al registrar log:', err.message);
        res.status(500).json({ error: 'Error interno al registrar el evento.' });
    }
});

// ── GET /audit/logs ──────────────────────────
// Solo admin/auditor puede consultar (verificado en gateway)
app.get('/audit/logs', async (req, res) => {
    const limit    = Math.min(parseInt(req.query.limit)  || 50, 500);
    const offset   = parseInt(req.query.offset) || 0;
    const severity = req.query.severity;
    const userId   = req.query.userId;
    const action   = req.query.action;

    // Construcción dinámica SEGURA con parámetros posicionales
    const conditions = [];
    const params     = [];
    let   paramIndex = 1;

    if (severity && ['INFO', 'WARNING', 'ERROR', 'CRITICAL'].includes(severity)) {
        conditions.push(`severity = $${paramIndex++}`);
        params.push(severity);
    }
    if (userId && !isNaN(parseInt(userId))) {
        conditions.push(`user_id = $${paramIndex++}`);
        params.push(parseInt(userId));
    }
    if (action && typeof action === 'string') {
        // LIKE con parámetro para búsqueda parcial (seguro contra SQLi)
        conditions.push(`action ILIKE $${paramIndex++}`);
        params.push(`%${action.replace(/[%_]/g, '\\$&')}%`); // Escapar wildcards
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    params.push(limit);
    params.push(offset);

    try {
        const result = await pool.query(
            `SELECT id, user_id, action, resource, ip_address, severity, details, created_at
             FROM audit_logs
             ${whereClause}
             ORDER BY created_at DESC
             LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`,
            params
        );

        // Conteo total para paginación
        const countResult = await pool.query(
            `SELECT COUNT(*) FROM audit_logs ${whereClause}`,
            params.slice(0, -2)
        );

        res.json({
            logs:       result.rows,
            pagination: {
                limit,
                offset,
                count: result.rows.length,
                total: parseInt(countResult.rows[0].count)
            }
        });

    } catch (err) {
        console.error('[AUDIT] Error al obtener logs:', err.message);
        res.status(500).json({ error: 'Error interno.' });
    }
});

// ── GET /audit/logs/stats ────────────────────
// Estadísticas de seguridad para el dashboard de administración
app.get('/audit/logs/stats', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT
                severity,
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '24 hours') AS last_24h,
                COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '1 hour')   AS last_hour
            FROM audit_logs
            GROUP BY severity
            ORDER BY CASE severity
                WHEN 'CRITICAL' THEN 1
                WHEN 'ERROR'    THEN 2
                WHEN 'WARNING'  THEN 3
                WHEN 'INFO'     THEN 4
            END
        `);

        const topActions = await pool.query(`
            SELECT action, COUNT(*) AS count
            FROM audit_logs
            WHERE created_at > NOW() - INTERVAL '24 hours'
            GROUP BY action
            ORDER BY count DESC
            LIMIT 10
        `);

        res.json({
            bySeverity: result.rows,
            topActions: topActions.rows,
            generatedAt: new Date().toISOString()
        });

    } catch (err) {
        console.error('[AUDIT] Error al generar stats:', err.message);
        res.status(500).json({ error: 'Error interno.' });
    }
});

// =============================================
// INICIO DEL SERVIDOR
// =============================================
app.listen(PORT, () => {
    console.log(`[AUDIT-SERVICE] Escuchando en puerto ${PORT}`);
});
