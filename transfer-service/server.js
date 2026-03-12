'use strict';
require('dotenv').config();

const express  = require('express');
const jwt      = require('jsonwebtoken');
const { Pool } = require('pg');

const app  = express();
const PORT = process.env.TRANSFER_PORT || 3002;

app.use(express.json());

// Conexión a la base de datos
const pool = new Pool({
    host:     process.env.DB_HOST     || 'postgres',
    port:     parseInt(process.env.DB_PORT) || 5432,
    database: process.env.POSTGRES_DB || 'securepay_db',
    user:     process.env.POSTGRES_USER,
    password: process.env.POSTGRES_PASSWORD
});

// ── MIDDLEWARE: Verificación JWT ─────────────
function authenticate(req, res, next) {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Token requerido.' });
    }
    try {
        const decoded = jwt.verify(authHeader.split(' ')[1], process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch {
        res.status(401).json({ error: 'Token inválido o expirado.' });
    }
}

// ── GET /transfer/balance ────────────────────
app.get('/transfer/balance', authenticate, async (req, res) => {
    try {
        // CONFIDENCIALIDAD: solo puede ver su propia cuenta
        const result = await pool.query(
            'SELECT account_number, balance, currency FROM accounts WHERE user_id = $1',
            [req.user.userId]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Cuenta no encontrada.' });
        }
        res.json({ account: result.rows[0] });
    } catch (err) {
        console.error('[TRANSFER] Error balance:', err.message);
        res.status(500).json({ error: 'Error interno.' });
    }
});

// ── POST /transfer/create ────────────────────
app.post('/transfer/create', authenticate, async (req, res) => {
    const { toAccountNumber, amount, description } = req.body;

    if (!toAccountNumber || !amount || isNaN(amount) || amount <= 0) {
        return res.status(400).json({ error: 'toAccountNumber y amount (> 0) son requeridos.' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // Cuenta origen (bloqueo FOR UPDATE para evitar condición de carrera)
        const fromResult = await client.query(
            'SELECT id, account_number, balance FROM accounts WHERE user_id = $1 FOR UPDATE',
            [req.user.userId]
        );
        if (fromResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Cuenta de origen no encontrada.' });
        }
        const fromAccount = fromResult.rows[0];

        if (fromAccount.account_number === toAccountNumber) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'No puedes transferir a tu propia cuenta.' });
        }

        // INTEGRIDAD: Verificar saldo
        if (parseFloat(fromAccount.balance) < parseFloat(amount)) {
            await client.query('ROLLBACK');
            return res.status(422).json({ error: 'Saldo insuficiente.' });
        }

        // Cuenta destino (Anti-SQLi: parámetro $1)
        const toResult = await client.query(
            'SELECT id FROM accounts WHERE account_number = $1 FOR UPDATE',
            [toAccountNumber]
        );
        if (toResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Cuenta de destino no encontrada.' });
        }
        const toAccount = toResult.rows[0];

        // Registrar transferencia
        const transferResult = await client.query(
            `INSERT INTO transfers (from_account_id, to_account_id, amount, description, status)
             VALUES ($1, $2, $3, $4, 'pending') RETURNING id`,
            [fromAccount.id, toAccount.id, amount, description || null]
        );
        const transferId = transferResult.rows[0].id;

        // Mover el dinero (operación atómica)
        await client.query('UPDATE accounts SET balance = balance - $1 WHERE id = $2', [amount, fromAccount.id]);
        await client.query('UPDATE accounts SET balance = balance + $1 WHERE id = $2', [amount, toAccount.id]);

        // Marcar como completada
        await client.query("UPDATE transfers SET status = 'completed' WHERE id = $1", [transferId]);

        await client.query('COMMIT');

        res.status(201).json({
            message: 'Transferencia completada.',
            transfer: { id: transferId, from: fromAccount.account_number, to: toAccountNumber, amount, status: 'completed' }
        });

    } catch (err) {
        await client.query('ROLLBACK');
        console.error('[TRANSFER] Error transferencia:', err.message);
        res.status(500).json({ error: 'Error interno al procesar la transferencia.' });
    } finally {
        client.release();
    }
});

// ── GET /transfer/history ────────────────────
app.get('/transfer/history', authenticate, async (req, res) => {
    try {
        // CONFIDENCIALIDAD: solo sus propias transferencias
        const result = await pool.query(
            `SELECT t.id, t.amount, t.description, t.status, t.created_at,
                    a_from.account_number AS from_account,
                    a_to.account_number   AS to_account
             FROM transfers t
             JOIN accounts a_from ON a_from.id = t.from_account_id
             JOIN accounts a_to   ON a_to.id   = t.to_account_id
             WHERE a_from.user_id = $1 OR a_to.user_id = $1
             ORDER BY t.created_at DESC
             LIMIT 50`,
            [req.user.userId]
        );
        res.json({ transfers: result.rows });
    } catch (err) {
        console.error('[TRANSFER] Error historial:', err.message);
        res.status(500).json({ error: 'Error interno.' });
    }
});

app.listen(PORT, () => console.log(`[TRANSFER-SERVICE] Puerto ${PORT}`));
