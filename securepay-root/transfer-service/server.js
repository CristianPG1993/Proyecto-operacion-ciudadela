'use strict';
require('dotenv').config();

const express  = require('express');
const helmet   = require('helmet');
const cors     = require('cors');
const crypto   = require('crypto');
const axios    = require('axios');
const { Pool } = require('pg');
const { body, param, validationResult } = require('express-validator');

const app  = express();
const PORT = process.env.TRANSFER_SERVICE_PORT || 3002;

const AUDIT_SERVICE_URL = process.env.AUDIT_SERVICE_URL || 'http://audit-logs:3003';

// =============================================
// SEGURIDAD: Cabeceras y parseo
// =============================================
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '5kb' }));

// =============================================
// CONEXIÓN A BASE DE DATOS (Mínimo Privilegio)
// Usa usuario transfer_svc con permisos restringidos
// =============================================
const pool = new Pool({
    host:     process.env.DB_HOST     || 'postgres',
    port:     parseInt(process.env.DB_PORT) || 5432,
    database: process.env.POSTGRES_DB || 'securepay_db',
    user:     'transfer_svc',
    password: 'Transfer_Svc_P@ss_2024!',
    max:      10,
    idleTimeoutMillis: 30000
});

pool.connect()
    .then(client => {
        console.log('[TRANSFER-SERVICE] Conectado a PostgreSQL');
        client.release();
    })
    .catch(err => console.error('[TRANSFER-SERVICE] Error DB:', err.message));

// =============================================
// INTEGRIDAD: Función para generar hash SHA-256
// Garantiza que los datos de la transferencia no sean manipulados
// =============================================
function generateIntegrityHash(fromAccountId, toAccountId, amount, timestamp) {
    const data = `${fromAccountId}|${toAccountId}|${amount}|${timestamp}`;
    return crypto.createHash('sha256').update(data).digest('hex');
}

function verifyIntegrityHash(fromAccountId, toAccountId, amount, timestamp, hash) {
    const expectedHash = generateIntegrityHash(fromAccountId, toAccountId, amount, timestamp);
    // Comparación en tiempo constante para evitar timing attacks
    return crypto.timingSafeEqual(
        Buffer.from(expectedHash, 'hex'),
        Buffer.from(hash,         'hex')
    );
}

// =============================================
// HELPER: Registrar evento de auditoría
// =============================================
async function logAuditEvent(userId, action, resource, ipAddress, details, severity = 'INFO') {
    try {
        await axios.post(`${AUDIT_SERVICE_URL}/audit/log`, {
            userId, action, resource, ipAddress, details, severity
        }, { timeout: 3000 });
    } catch (err) {
        // La auditoría no debe bloquear la operación principal
        console.error('[TRANSFER] Error al registrar auditoría:', err.message);
    }
}

// =============================================
// VALIDACIONES
// =============================================
function handleValidation(req, res, next) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    next();
}

const transferValidation = [
    body('toAccountNumber')
        .trim()
        .notEmpty()
        .withMessage('La cuenta destino es requerida.')
        .matches(/^ACC-\d+$/)
        .withMessage('Formato de cuenta inválido.'),
    body('amount')
        .isFloat({ min: 0.01, max: 50000 })
        .withMessage('El monto debe estar entre 0.01 y 50,000.'),
    body('description')
        .optional()
        .trim()
        .isLength({ max: 200 })
        .withMessage('La descripción no puede superar 200 caracteres.')
        .escape() // Escapar caracteres HTML (Anti-XSS)
];

// =============================================
// RUTAS
// =============================================

// Health check
app.get('/transfer/health', (req, res) => {
    res.json({ service: 'transfer-service', status: 'ok', timestamp: new Date().toISOString() });
});

// ── POST /transfer/create ────────────────────
// CONFIDENCIALIDAD: Solo usuarios autenticados (verificado por gateway)
// INTEGRIDAD: Hash SHA-256 + consultas parametrizadas + transacción atómica
// DISPONIBILIDAD: Manejo de errores + rollback automático
app.post('/transfer/create', transferValidation, handleValidation, async (req, res) => {
    const userId      = parseInt(req.headers['x-user-id']);
    const { toAccountNumber, amount, description } = req.body;
    const ipAddress   = req.ip || req.connection.remoteAddress;
    const client      = await pool.connect();

    try {
        await client.query('BEGIN');

        // 1. Obtener cuenta origen del usuario autenticado (Anti-SQLi: $1 parametrizado)
        const fromAccountResult = await client.query(
            `SELECT id, account_number, balance
             FROM accounts
             WHERE user_id = $1 AND is_active = TRUE
             FOR UPDATE`,  // Bloqueo pesimista para evitar double-spend
            [userId]
        );

        if (fromAccountResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Cuenta de origen no encontrada.' });
        }
        const fromAccount = fromAccountResult.rows[0];

        // 2. Verificar que no está enviando a su propia cuenta
        if (fromAccount.account_number === toAccountNumber) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'No puedes transferir a tu propia cuenta.' });
        }

        // 3. INTEGRIDAD: Verificar saldo suficiente
        if (parseFloat(fromAccount.balance) < parseFloat(amount)) {
            await client.query('ROLLBACK');
            await logAuditEvent(userId, 'TRANSFER_FAILED_INSUFFICIENT_FUNDS', fromAccount.account_number, ipAddress,
                { amount, reason: 'Saldo insuficiente' }, 'WARNING');
            return res.status(422).json({ error: 'Saldo insuficiente para realizar la transferencia.' });
        }

        // 4. Obtener cuenta destino (Anti-SQLi: $1 parametrizado)
        const toAccountResult = await client.query(
            `SELECT id, account_number, user_id
             FROM accounts
             WHERE account_number = $1 AND is_active = TRUE
             FOR UPDATE`,
            [toAccountNumber]
        );

        if (toAccountResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Cuenta de destino no encontrada.' });
        }
        const toAccount = toAccountResult.rows[0];

        // 5. INTEGRIDAD: Generar hash de la transferencia
        const timestamp = new Date().toISOString();
        const integrityHash = generateIntegrityHash(fromAccount.id, toAccount.id, amount, timestamp);

        // 6. Crear registro de transferencia
        const transferResult = await client.query(
            `INSERT INTO transfers (from_account_id, to_account_id, amount, description, status, integrity_hash, initiated_by)
             VALUES ($1, $2, $3, $4, 'pending', $5, $6)
             RETURNING id`,
            [fromAccount.id, toAccount.id, amount, description || null, integrityHash, userId]
        );
        const transferId = transferResult.rows[0].id;

        // 7. Debitar cuenta origen
        await client.query(
            'UPDATE accounts SET balance = balance - $1 WHERE id = $2',
            [amount, fromAccount.id]
        );

        // 8. Acreditar cuenta destino
        await client.query(
            'UPDATE accounts SET balance = balance + $1 WHERE id = $2',
            [amount, toAccount.id]
        );

        // 9. Marcar transferencia como completada
        await client.query(
            `UPDATE transfers SET status = 'completed', completed_at = NOW() WHERE id = $1`,
            [transferId]
        );

        await client.query('COMMIT');

        // 10. Auditoría post-transacción
        await logAuditEvent(userId, 'TRANSFER_COMPLETED', `transfer/${transferId}`, ipAddress, {
            transferId,
            from:   fromAccount.account_number,
            to:     toAccountNumber,
            amount: parseFloat(amount),
            integrityHash
        }, 'INFO');

        res.status(201).json({
            message: 'Transferencia realizada con éxito.',
            transfer: {
                id:              transferId,
                from:            fromAccount.account_number,
                to:              toAccountNumber,
                amount:          parseFloat(amount),
                description:     description || '',
                status:          'completed',
                integrityHash,
                timestamp
            }
        });

    } catch (err) {
        await client.query('ROLLBACK');
        console.error('[TRANSFER] Error en transferencia:', err.message);
        await logAuditEvent(userId, 'TRANSFER_ERROR', 'transfer/create', ipAddress,
            { error: err.message }, 'ERROR');
        res.status(500).json({ error: 'Error interno al procesar la transferencia.' });
    } finally {
        client.release();
    }
});

// ── GET /transfer/balance ────────────────────
app.get('/transfer/balance', async (req, res) => {
    const userId = parseInt(req.headers['x-user-id']);

    try {
        // CONFIDENCIALIDAD: Solo puede ver su propia cuenta
        const result = await pool.query(
            `SELECT account_number, balance, currency
             FROM accounts
             WHERE user_id = $1 AND is_active = TRUE`,
            [userId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Cuenta no encontrada.' });
        }

        res.json({ account: result.rows[0] });

    } catch (err) {
        console.error('[TRANSFER] Error al consultar saldo:', err.message);
        res.status(500).json({ error: 'Error interno.' });
    }
});

// ── GET /transfer/history ────────────────────
app.get('/transfer/history', async (req, res) => {
    const userId = parseInt(req.headers['x-user-id']);
    const limit  = Math.min(parseInt(req.query.limit) || 20, 100); // Máx 100 resultados
    const offset = parseInt(req.query.offset) || 0;

    try {
        // CONFIDENCIALIDAD: Solo ve sus propias transferencias
        const result = await pool.query(
            `SELECT t.id, t.amount, t.description, t.status,
                    t.integrity_hash, t.created_at, t.completed_at,
                    a_from.account_number AS from_account,
                    a_to.account_number   AS to_account,
                    CASE
                        WHEN a_from.user_id = $1 THEN 'sent'
                        ELSE 'received'
                    END AS direction
             FROM transfers t
             JOIN accounts a_from ON a_from.id = t.from_account_id
             JOIN accounts a_to   ON a_to.id   = t.to_account_id
             WHERE a_from.user_id = $1 OR a_to.user_id = $1
             ORDER BY t.created_at DESC
             LIMIT $2 OFFSET $3`,
            [userId, limit, offset]
        );

        res.json({
            transfers: result.rows,
            pagination: { limit, offset, count: result.rows.length }
        });

    } catch (err) {
        console.error('[TRANSFER] Error al obtener historial:', err.message);
        res.status(500).json({ error: 'Error interno.' });
    }
});

// ── GET /transfer/verify/:id ─────────────────
// INTEGRIDAD: Verificar que una transferencia no fue manipulada
app.get('/transfer/verify/:id', async (req, res) => {
    const transferId = parseInt(req.params.id);
    const userId     = parseInt(req.headers['x-user-id']);

    if (isNaN(transferId)) {
        return res.status(400).json({ error: 'ID de transferencia inválido.' });
    }

    try {
        const result = await pool.query(
            `SELECT t.*, a_from.user_id AS owner_id
             FROM transfers t
             JOIN accounts a_from ON a_from.id = t.from_account_id
             WHERE t.id = $1`,
            [transferId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Transferencia no encontrada.' });
        }

        const transfer = result.rows[0];

        // Solo el emisor puede verificar su transferencia
        if (transfer.owner_id !== userId && req.headers['x-user-role'] !== 'admin') {
            return res.status(403).json({ error: 'Acceso denegado.' });
        }

        // Recalcular hash y comparar
        const timestamp    = new Date(transfer.created_at).toISOString();
        const expectedHash = generateIntegrityHash(
            transfer.from_account_id,
            transfer.to_account_id,
            transfer.amount,
            timestamp
        );

        const integrityOk = transfer.integrity_hash === expectedHash;

        res.json({
            transferId,
            status:      transfer.status,
            integrityOk,
            storedHash:  transfer.integrity_hash,
            computedHash: expectedHash,
            message: integrityOk
                ? 'La transferencia no ha sido manipulada.'
                : 'ALERTA: La integridad de la transferencia está comprometida.'
        });

    } catch (err) {
        console.error('[TRANSFER] Error al verificar integridad:', err.message);
        res.status(500).json({ error: 'Error interno.' });
    }
});

// =============================================
// INICIO DEL SERVIDOR
// =============================================
app.listen(PORT, () => {
    console.log(`[TRANSFER-SERVICE] Escuchando en puerto ${PORT}`);
});
