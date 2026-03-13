import pkg from 'pg';
const { Pool } = pkg;
import dotenv from 'dotenv';

dotenv.config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? {
    rejectUnauthorized: false
  } : false,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
  statement_timeout: 60000,
  query_timeout: 60000
});

// Обработчик ошибок пула
pool.on('error', (err) => {
  console.error('Pool error:', err.message);
});

// Логирование подключений
if (process.env.NODE_ENV !== 'production') {
  pool.on('connect', () => console.log('DB: connected'));
  pool.on('remove', () => console.log('DB: disconnected'));
}

/**
 * Выполнение SQL-запроса через пул подключений
 */
export async function query(text, params) {
  try {
    return await pool.query(text, params);
  } catch (err) {
    console.error('Query error:', err.message);
    throw err;
  }
}

/**
 * Проверка соединения с базой данных
 */
export async function checkConnection() {
  let client;
  try {
    client = await pool.connect();
    await client.query('SELECT NOW()');
    return true;
  } catch (error) {
    console.error('Connection failed:', error.message);
    return false;
  } finally {
    if (client) client.release();
  }
}

/**
 * Статистика пула подключений
 */
export function getPoolStats() {
  return {
    totalCount: pool.totalCount,
    idleCount: pool.idleCount,
    waitingCount: pool.waitingCount
  };
}

export default pool;