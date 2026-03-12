'use strict';
require('dotenv').config();

const { Pool } = require('pg');

// Simulación de DB con Prepared Statements
const pool = new Pool({
    host:     process.env.DB_HOST     || 'postgres',
    port:     parseInt(process.env.DB_PORT) || 5432,
    database: process.env.POSTGRES_DB || 'securepay_db',
    user:     'transfer_svc',
    password: 'Transfer_Svc_P@ss_2024!'
});

module.exports = {
    query: (text, params) => pool.query(text, params)
};
