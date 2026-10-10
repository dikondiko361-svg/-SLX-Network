'use strict';

/**
 * SLX Network v1.8.2 — backend
 * Compatible with the matching v1.8.2 index.html.
 * Requires Node.js 22.13+ and: express, cors, bcryptjs, jsonwebtoken, pg
 *
 * Production environment variables:
 *   DATABASE_URL  PostgreSQL connection string (required in production)
 *   JWT_SECRET    Long random secret (required in production)
 *   PORT          Optional; Render supplies this automatically
 */

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');
const { Pool } = require('pg');

const app = express();
const VERSION = '1.8.2';
const NETWORK = 'SLX-Testnet';
const FEE = 0.1;
const FAUCET_AMOUNT = 10;
const FAUCET_COOLDOWN_MS = 24 * 60 * 60 * 1000;
const MAX_SUPPLY = 21_000_000;
const DECIMALS = 8;
const UNIT = 10 ** DECIMALS;
const GENESIS_HASH = 'SLX_GENESIS_1_8_2';
const PORT = Number(process.env.PORT) || 3000;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const DATABASE_URL = process.env.DATABASE_URL || '';
const JWT_SECRET = process.env.JWT_SECRET || (IS_PRODUCTION ? '' : crypto.randomBytes(32).toString('hex'));
const GLOBAL_MUTATION_LOCK = 731_820_182;

if (IS_PRODUCTION && !JWT_SECRET) {
  throw new Error('JWT_SECRET is required in production. Set a long random secret in your hosting environment.');
}
if (IS_PRODUCTION && !DATABASE_URL) {
  throw new Error('DATABASE_URL is required in production. Configure PostgreSQL to avoid losing accounts and balances after a restart.');
}

app.disable('x-powered-by');
app.use(cors());
app.use(express.json({ limit: '32kb' }));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Cache-Control', 'no-store');
  next();
});

let pool = null;
let dbUserColumns = new Set();
let memoryMutationQueue = Promise.resolve();

const memory = {
  users: [],
  wallets: [],
  transactions: [],
  blocks: [],
  faucetClaims: [],
  nextUserId: 1,
  nextWalletId: 1,
  nextTransactionId: 1,
  nextBlockId: 1
};

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function fail(status, message) {
  throw new HttpError(status, message);
}

function normalizeUsername(value) {
  return String(value ?? '').trim().toLowerCase();
}

function validateUsername(value) {
  const username = normalizeUsername(value);

  if (!/^[a-z0-9_.-]{3,24}$/.test(username)) {
    fail(400, 'Имя пользователя должно содержать 3–24 символа: латинские буквы, цифры, точку, дефис или подчёркивание.');
  }

  return username;
}

function validatePassword(value) {
  if (typeof value !== 'string' || value.length < 6 || value.length > 128) {
    fail(400, 'Пароль должен содержать от 6 до 128 символов.');
  }

  return value;
}

function normalizeRecoveryCode(value) {
  return String(value ?? '').trim().toUpperCase().replace(/[\s-]/g, '');
}

function createRecoveryCode() {
  return crypto.randomBytes(16).toString('hex').toUpperCase();
}

function createWalletAddress() {
  return 'SLXC' + crypto.randomBytes(16).toString('hex').toUpperCase();
}

function validateAddress(value) {
  const address = String(value ?? '').trim().toUpperCase();

  if (!/^SLXC[A-F0-9]{32}$/.test(address)) {
    fail(400, 'Неверный адрес кошелька SLX.');
  }

  return address;
}

function amountToUnits(value) {
  const amount = typeof value === 'number'
    ? value
    : Number(String(value ?? '').replace(',', '.'));

  if (!Number.isFinite(amount) || amount <= 0) {
    fail(400, 'Сумма должна быть больше нуля.');
  }

  const units = Math.round(amount * UNIT);

  if (
    !Number.isSafeInteger(units) ||
    units <= 0 ||
    Math.abs(amount - units / UNIT) > 1e-10
  ) {
    fail(400, `Максимальная точность суммы — ${DECIMALS} знаков после запятой.`);
  }

  return units;
}

function unitsToAmount(units) {
  return Number((units / UNIT).toFixed(DECIMALS));
}

function amountToDb(units) {
  const integerUnits = Number(units);

  if (!Number.isSafeInteger(integerUnits) || integerUnits < 0) {
    throw new Error('Внутренняя ошибка точности SLX.');
  }

  const whole = Math.floor(integerUnits / UNIT);
  const fraction = String(integerUnits % UNIT).padStart(DECIMALS, '0');

  return `${whole}.${fraction}`;
}

function dbAmountToUnits(value) {
  const amount = Number(value ?? 0);

  if (!Number.isFinite(amount)) return 0;

  return Math.round(amount * UNIT);
}

function sha256(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function makeBlockHash(blockIndex, previousHash, timestamp, data) {
  const iso = new Date(timestamp).toISOString();

  return sha256(`${blockIndex}|${previousHash}|${iso}|${data}`);
}

function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    created_at: user.created_at || user.createdAt || new Date().toISOString()
  };
}

function publicWallet(wallet) {
  return {
    id: wallet.id,
    user_id: wallet.user_id ?? wallet.userId,
    address: wallet.address,
    balance: Number(wallet.balance || 0),
    created_at: wallet.created_at || wallet.createdAt || new Date().toISOString()
  };
}

function publicBlock(block) {
  return {
    id: block.id,
    block_index: Number(block.block_index ?? block.blockIndex ?? 0),
    hash: block.hash,
    previous_hash: block.previous_hash ?? block.previousHash ?? '0',
    transaction_count: Number(block.transaction_count ?? block.transactionCount ?? 0),
    timestamp: block.timestamp || block.created_at || block.createdAt || new Date().toISOString(),
    data: block.data || ''
  };
}

function signToken(user) {
  return jwt.sign(
    { sub: String(user.id), username: user.username },
    JWT_SECRET,
    { expiresIn: '7d', issuer: 'slx-network' }
  );
}

async function findUserById(userId) {
  if (pool) {
    const result = await pool.query(
      'SELECT id, username, password_hash, recovery_hash, recovery_code, created_at FROM users WHERE id = $1 LIMIT 1',
      [userId]
    );

    return result.rows[0] || null;
  }

  return memory.users.find(user => String(user.id) === String(userId)) || null;
}

async function authenticate(req, res, next) {
  try {
    const authorization = String(req.headers.authorization || '');
    const match = authorization.match(/^Bearer\s+(.+)$/i);

    if (!match) {
      fail(401, 'Нужна авторизация. Войди в аккаунт.');
    }

    let payload;

    try {
      payload = jwt.verify(match[1], JWT_SECRET, { issuer: 'slx-network' });
    } catch {
      fail(401, 'Сессия истекла. Войди снова.');
    }

    const user = await findUserById(payload.sub);

    if (!user) {
      fail(401, 'Аккаунт не найден. Войди снова.');
    }

    req.user = user;
    req.token = match[1];

    next();
  } catch (error) {
    next(error);
  }
}

async function withMemoryMutation(fn) {
  const previous = memoryMutationQueue;
  let release;

  memoryMutationQueue = new Promise(resolve => {
    release = resolve;
  });

  await previous;

  try {
    return await fn();
  } finally {
    release();
  }
}

async function withPgMutation(fn) {
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    // Prevent concurrent balance changes from causing double-spends.
    await client.query('SELECT pg_advisory_xact_lock($1)', [GLOBAL_MUTATION_LOCK]);

    const result = await fn(client);

    await client.query('COMMIT');

    return result;
  } catch (error) {
    try {
      await client.query('ROLLBACK');
    } catch {}

    throw error;
  } finally {
    client.release();
  }
}

async function withMutation(pgFn, memoryFn) {
  if (pool) return withPgMutation(pgFn);

  return withMemoryMutation(memoryFn);
}

async function initDatabase() {
  if (!DATABASE_URL) {
    console.warn(
      '[SLX] DATABASE_URL is not set; using temporary in-memory storage. Data will be lost when the process restarts.'
    );

    const now = new Date().toISOString();

    memory.blocks.push({
      id: memory.nextBlockId++,
      block_index: 0,
      hash: GENESIS_HASH,
      previous_hash: '0',
      transaction_count: 0,
      timestamp: now,
      data: 'genesis'
    });

    return;
  }

  pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: IS_PRODUCTION ? { rejectUnauthorized: false } : undefined,
    max: 10,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 10_000
  });

  await pool.query('SELECT 1');

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      recovery_code TEXT,
      recovery_hash TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS wallets (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      address TEXT NOT NULL UNIQUE,
      balance NUMERIC(24,8) NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS transactions (
      id BIGSERIAL PRIMARY KEY,
      tx_hash TEXT,
      hash TEXT,
      from_wallet TEXT NOT NULL,
      to_wallet TEXT NOT NULL,
      amount NUMERIC(24,8) NOT NULL,
      fee NUMERIC(24,8) NOT NULL DEFAULT 0,
      type TEXT NOT NULL DEFAULT 'SEND',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS blocks (
      id BIGSERIAL PRIMARY KEY,
      block_index BIGINT NOT NULL UNIQUE,
      hash TEXT NOT NULL,
      previous_hash TEXT NOT NULL,
      transaction_count INTEGER NOT NULL DEFAULT 0,
      timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      data TEXT NOT NULL DEFAULT ''
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS faucet_claims (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      wallet_id BIGINT NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
      claimed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  // Add missing fields without deleting existing account or wallet data.
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS recovery_code TEXT`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS recovery_hash TEXT`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()`);

  await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS user_id BIGINT`);
  await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS address TEXT`);
  await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS balance NUMERIC(24,8) DEFAULT 0`);
  await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()`);

  await pool.query(`ALTER TABLE transactions ADD COLUMN IF NOT EXISTS tx_hash TEXT`);
  await pool.query(`ALTER TABLE transactions ADD COLUMN IF NOT EXISTS hash TEXT`);
  await pool.query(`ALTER TABLE transactions ADD COLUMN IF NOT EXISTS from_wallet TEXT`);
  await pool.query(`ALTER TABLE transactions ADD COLUMN IF NOT EXISTS to_wallet TEXT`);
  await pool.query(`ALTER TABLE transactions ADD COLUMN IF NOT EXISTS amount NUMERIC(24,8) DEFAULT 0`);
  await pool.query(`ALTER TABLE transactions ADD COLUMN IF NOT EXISTS fee NUMERIC(24,8) DEFAULT 0`);
  await pool.query(`ALTER TABLE transactions ADD COLUMN IF NOT EXISTS type TEXT DEFAULT 'SEND'`);
  await pool.query(`ALTER TABLE transactions ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ`);
  await pool.query(`ALTER TABLE transactions ADD COLUMN IF NOT EXISTS timestamp TIMESTAMPTZ`);

  await pool.query(`ALTER TABLE blocks ADD COLUMN IF NOT EXISTS block_index BIGINT`);
  await pool.query(`ALTER TABLE blocks ADD COLUMN IF NOT EXISTS hash TEXT`);
  await pool.query(`ALTER TABLE blocks ADD COLUMN IF NOT EXISTS previous_hash TEXT DEFAULT '0'`);
  await pool.query(`ALTER TABLE blocks ADD COLUMN IF NOT EXISTS transaction_count INTEGER DEFAULT 0`);
  await pool.query(`ALTER TABLE blocks ADD COLUMN IF NOT EXISTS timestamp TIMESTAMPTZ`);
  await pool.query(`ALTER TABLE blocks ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ`);
  await pool.query(`ALTER TABLE blocks ADD COLUMN IF NOT EXISTS data TEXT DEFAULT ''`);

  await pool.query(`ALTER TABLE faucet_claims ADD COLUMN IF NOT EXISTS user_id BIGINT`);
  await pool.query(`ALTER TABLE faucet_claims ADD COLUMN IF NOT EXISTS wallet_id BIGINT`);
  await pool.query(`ALTER TABLE faucet_claims ADD COLUMN IF NOT EXISTS claimed_at TIMESTAMPTZ`);
  await pool.query(`ALTER TABLE faucet_claims ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ`);

  const columnsResult = await pool.query(`
    SELECT column_name
    FROM information_schema.columns
    WHERE table_schema = current_schema() AND table_name = 'users'
  `);

  dbUserColumns = new Set(columnsResult.rows.map(row => row.column_name));

  if (dbUserColumns.has('password')) {
    await pool.query(`
      UPDATE users
      SET password_hash = password
      WHERE password_hash IS NULL AND password IS NOT NULL
    `);
  }

  await pool.query(`UPDATE users SET created_at = NOW() WHERE created_at IS NULL`);
  await pool.query(`UPDATE wallets SET balance = 0 WHERE balance IS NULL`);
  await pool.query(`UPDATE transactions SET amount = 0 WHERE amount IS NULL`);
  await pool.query(`UPDATE transactions SET fee = 0 WHERE fee IS NULL`);

  // If an older version used `timestamp`, keep the original timestamps.
  await pool.query(`
    UPDATE transactions
    SET created_at = COALESCE(created_at, timestamp, NOW())
    WHERE created_at IS NULL
  `);

  await pool.query(`
    UPDATE transactions
    SET timestamp = COALESCE(timestamp, created_at, NOW())
    WHERE timestamp IS NULL
  `);

  await pool.query(`ALTER TABLE transactions ALTER COLUMN created_at SET DEFAULT NOW()`);
  await pool.query(`ALTER TABLE transactions ALTER COLUMN timestamp SET DEFAULT NOW()`);

  await pool.query(`UPDATE blocks SET previous_hash = '0' WHERE previous_hash IS NULL`);
  await pool.query(`UPDATE blocks SET transaction_count = 0 WHERE transaction_count IS NULL`);

  await pool.query(`
    UPDATE blocks
    SET timestamp = COALESCE(timestamp, created_at, NOW())
    WHERE timestamp IS NULL
  `);

  await pool.query(`
    UPDATE blocks
    SET created_at = COALESCE(created_at, timestamp, NOW())
    WHERE created_at IS NULL
  `);

  await pool.query(`ALTER TABLE blocks ALTER COLUMN timestamp SET DEFAULT NOW()`);
  await pool.query(`ALTER TABLE blocks ALTER COLUMN created_at SET DEFAULT NOW()`);
  await pool.query(`UPDATE blocks SET data = '' WHERE data IS NULL`);

  await pool.query(`
    UPDATE faucet_claims
    SET claimed_at = COALESCE(claimed_at, created_at, NOW())
    WHERE claimed_at IS NULL
  `);

  await pool.query(`
    UPDATE faucet_claims
    SET created_at = COALESCE(created_at, claimed_at, NOW())
    WHERE created_at IS NULL
  `);

  await pool.query(`ALTER TABLE faucet_claims ALTER COLUMN claimed_at SET DEFAULT NOW()`);
  await pool.query(`ALTER TABLE faucet_claims ALTER COLUMN created_at SET DEFAULT NOW()`);

  await pool.query(`CREATE INDEX IF NOT EXISTS wallets_user_id_idx ON wallets(user_id)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS transactions_from_wallet_idx ON transactions(from_wallet)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS transactions_to_wallet_idx ON transactions(to_wallet)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS faucet_claims_user_claimed_idx ON faucet_claims(user_id, claimed_at DESC)`);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS blocks_block_index_unique_idx ON blocks(block_index)`);

  const genesis = await pool.query('SELECT id FROM blocks WHERE block_index = 0 LIMIT 1');

  if (!genesis.rows.length) {
    const timestamp = new Date();

    await pool.query(
      `INSERT INTO blocks
         (block_index, hash, previous_hash, transaction_count, timestamp, created_at, data)
       VALUES (0, $1, '0', 0, $2, $2, 'genesis')`,
      [GENESIS_HASH, timestamp]
    );
  }

  console.log('[SLX] PostgreSQL connected; persistent storage enabled.');
}

async function getWalletRowsForUser(userId) {
  if (pool) {
    const result = await pool.query(
      `SELECT id, user_id, address, balance, created_at
       FROM wallets
       WHERE user_id = $1
       ORDER BY id ASC`,
      [userId]
    );

    return result.rows.map(publicWallet);
  }

  return memory.wallets
    .filter(wallet => String(wallet.user_id) === String(userId))
    .sort((a, b) => Number(a.id) - Number(b.id))
    .map(publicWallet);
}

async function getWalletForUser(walletId, userId, client = null) {
  if (pool) {
    const db = client || pool;

    const result = await db.query(
      `SELECT id, user_id, address, balance, created_at
       FROM wallets
       WHERE id = $1 AND user_id = $2
       LIMIT 1`,
      [walletId, userId]
    );

    return result.rows[0] || null;
  }

  return memory.wallets.find(wallet =>
    String(wallet.id) === String(walletId) &&
    String(wallet.user_id) === String(userId)
  ) || null;
}

async function createPgWallet(client, userId) {
  let address;

  for (let attempt = 0; attempt < 5; attempt++) {
    address = createWalletAddress();

    const exists = await client.query(
      'SELECT 1 FROM wallets WHERE address = $1 LIMIT 1',
      [address]
    );

    if (!exists.rows.length) break;

    address = null;
  }

  if (!address) {
    throw new Error('Не удалось создать уникальный адрес кошелька. Повтори попытку.');
  }

  const result = await client.query(
    `INSERT INTO wallets (user_id, address, balance, created_at)
     VALUES ($1, $2, 0, NOW())
     RETURNING id, user_id, address, balance, created_at`,
    [userId, address]
  );

  return result.rows[0];
}

function createMemoryWallet(userId) {
  let address;

  do {
    address = createWalletAddress();
  } while (memory.wallets.some(wallet => wallet.address === address));

  const wallet = {
    id: memory.nextWalletId++,
    user_id: userId,
    address,
    balance: 0,
    created_at: new Date().toISOString()
  };

  memory.wallets.push(wallet);

  return wallet;
}

async function addPgTransaction(client, data) {
  const txHash = crypto.randomBytes(32).toString('hex');

  const result = await client.query(
    `INSERT INTO transactions
       (tx_hash, hash, from_wallet, to_wallet, amount, fee, type, created_at, timestamp)
     VALUES ($1, $1, $2, $3, $4::numeric, $5::numeric, $6, NOW(), NOW())
     RETURNING id, tx_hash, hash, from_wallet, to_wallet, amount, fee, type, created_at, timestamp`,
    [
      txHash,
      data.from_wallet,
      data.to_wallet,
      amountToDb(data.amountUnits),
      amountToDb(data.feeUnits),
      data.type
    ]
  );

  return result.rows[0];
}

function addMemoryTransaction(data) {
  const txHash = crypto.randomBytes(32).toString('hex');
  const now = new Date().toISOString();

  const tx = {
    id: memory.nextTransactionId++,
    tx_hash: txHash,
    hash: txHash,
    from_wallet: data.from_wallet,
    to_wallet: data.to_wallet,
    amount: unitsToAmount(data.amountUnits),
    fee: unitsToAmount(data.feeUnits),
    type: data.type,
    created_at: now,
    timestamp: now
  };

  memory.transactions.push(tx);

  return tx;
}

async function addPgBlock(client, transactionCount, eventData) {
  const latest = await client.query(
    `SELECT block_index, hash
     FROM blocks
     ORDER BY block_index DESC
     LIMIT 1`
  );

  const previous = latest.rows[0] || { block_index: -1, hash: '0' };
  const blockIndex = Number(previous.block_index) + 1;
  const previousHash = previous.hash || '0';
  const timestamp = new Date();
  const data = JSON.stringify(eventData || {});
  const hash = makeBlockHash(blockIndex, previousHash, timestamp, data);

  const result = await client.query(
    `INSERT INTO blocks
       (block_index, hash, previous_hash, transaction_count, timestamp, created_at, data)
     VALUES ($1, $2, $3, $4, $5, $5, $6)
     RETURNING id, block_index, hash, previous_hash, transaction_count, timestamp, created_at, data`,
    [blockIndex, hash, previousHash, transactionCount, timestamp, data]
  );

  return result.rows[0];
}

function addMemoryBlock(transactionCount, eventData) {
  const previous = memory.blocks
    .slice()
    .sort((a, b) => Number(b.block_index) - Number(a.block_index))[0]
    || { block_index: -1, hash: '0' };

  const blockIndex = Number(previous.block_index) + 1;
  const previousHash = previous.hash || '0';
  const timestamp = new Date().toISOString();
  const data = JSON.stringify(eventData || {});

  const block = {
    id: memory.nextBlockId++,
    block_index: blockIndex,
    hash: makeBlockHash(blockIndex, previousHash, timestamp, data),
    previous_hash: previousHash,
    transaction_count: transactionCount,
    timestamp,
    created_at: timestamp,
    data
  };

  memory.blocks.push(block);

  return block;
}

async function currentSupply(client = null) {
  if (pool) {
    const db = client || pool;

    const result = await db.query(
      'SELECT COALESCE(SUM(balance), 0)::numeric AS supply FROM wallets'
    );

    return Number(result.rows[0]?.supply || 0);
  }

  return memory.wallets.reduce((sum, wallet) => sum + Number(wallet.balance || 0), 0);
}

async function makeStatus() {
  if (pool) {
    const result = await pool.query(`
      SELECT
        (SELECT COUNT(*)::int FROM users) AS users,
        (SELECT COUNT(*)::int FROM wallets) AS wallets,
        (SELECT COALESCE(MAX(block_index), 0)::bigint FROM blocks) AS height,
        (SELECT COALESCE(SUM(balance), 0)::numeric FROM wallets) AS supply
    `);

    const row = result.rows[0];
    const height = Number(row.height || 0);

    return {
      status: 'online',
      online: true,
      version: VERSION,
      network: NETWORK,
      height,
      blockHeight: height,
      users: Number(row.users || 0),
      wallets: Number(row.wallets || 0),
      supply: Number(row.supply || 0),
      transferFee: FEE,
      fee: FEE,
      faucetAmount: FAUCET_AMOUNT
    };
  }

  const height = memory.blocks.reduce(
    (max, block) => Math.max(max, Number(block.block_index)),
    0
  );

  const supply = await currentSupply();

  return {
    status: 'online',
    online: true,
    version: VERSION,
    network: NETWORK,
    height,
    blockHeight: height,
    users: memory.users.length,
    wallets: memory.wallets.length,
    supply,
    transferFee: FEE,
    fee: FEE,
    faucetAmount: FAUCET_AMOUNT,
    storage: 'memory',
    persistent: false
  };
}

async function getBlocks(limit = 50) {
  if (pool) {
    const result = await pool.query(
      `SELECT id, block_index, hash, previous_hash, transaction_count, timestamp, created_at, data
       FROM blocks
       ORDER BY block_index DESC
       LIMIT $1`,
      [limit]
    );

    return result.rows.map(publicBlock);
  }

  return memory.blocks
    .slice()
    .sort((a, b) => Number(b.block_index) - Number(a.block_index))
    .slice(0, limit)
    .map(publicBlock);
}

async function getWalletTransactions(wallet) {
  const address = wallet.address;
  let rows;

  if (pool) {
    const result = await pool.query(
      `SELECT id, tx_hash, hash, from_wallet, to_wallet, amount, fee, type, created_at, timestamp
       FROM transactions
       WHERE from_wallet = $1 OR to_wallet = $1
       ORDER BY created_at DESC, id DESC
       LIMIT 100`,
      [address]
    );

    rows = result.rows;
  } else {
    rows = memory.transactions
      .filter(tx => tx.from_wallet === address || tx.to_wallet === address)
      .sort((a, b) =>
        new Date(b.created_at) - new Date(a.created_at) ||
        Number(b.id) - Number(a.id)
      )
      .slice(0, 100);
  }

  return rows.map(tx => {
    const incoming = tx.to_wallet === address && tx.from_wallet !== address;
    let type = String(tx.type || 'SEND').toUpperCase();

    if (type !== 'FAUCET' && type !== 'GENESIS') {
      type = incoming ? 'RECEIVE' : 'SEND';
    }

    return {
      id: tx.id,
      hash: tx.tx_hash || tx.hash,
      from_wallet: tx.from_wallet,
      to_wallet: tx.to_wallet,
      amount: Number(tx.amount || 0),
      fee: Number(tx.fee || 0),
      type,
      created_at: tx.created_at || tx.timestamp,
      timestamp: tx.timestamp || tx.created_at
    };
  });
}

async function getChainVerification() {
  const blocks = pool
    ? (await pool.query(
        `SELECT block_index, hash, previous_hash, timestamp, data
         FROM blocks
         ORDER BY block_index ASC`
      )).rows
    : memory.blocks
        .slice()
        .sort((a, b) => Number(a.block_index) - Number(b.block_index));

  if (!blocks.length) {
    return {
      valid: false,
      verified: false,
      status: 'invalid',
      message: 'Цепочка пуста.'
    };
  }

  if (Number(blocks[0].block_index) !== 0 || blocks[0].hash !== GENESIS_HASH) {
    return {
      valid: false,
      verified: false,
      status: 'invalid',
      message: 'Неверный genesis-блок.'
    };
  }

  for (let i = 1; i < blocks.length; i++) {
    const previous = blocks[i - 1];
    const block = blocks[i];

    if (Number(block.block_index) !== Number(previous.block_index) + 1) {
      return {
        valid: false,
        verified: false,
        status: 'invalid',
        message: `Пропущена высота блока ${Number(previous.block_index) + 1}.`
      };
    }

    if (block.previous_hash !== previous.hash) {
      return {
        valid: false,
        verified: false,
        status: 'invalid',
        message: `Нарушена связь блока #${block.block_index}.`
      };
    }

    // Older records may not contain a canonical data payload.
    if (block.data) {
      const expected = makeBlockHash(
        block.block_index,
        block.previous_hash,
        block.timestamp,
        block.data
      );

      if (expected !== block.hash) {
        return {
          valid: false,
          verified: false,
          status: 'invalid',
          message: `Хеш блока #${block.block_index} не совпадает.`
        };
      }
    }
  }

  return {
    valid: true,
    verified: true,
    status: 'valid',
    height: Number(blocks[blocks.length - 1].block_index),
    blocks: blocks.length
  };
}

// Public pages and health checks.
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'), error => {
    if (error && !res.headersSent) {
      res.status(404).send('index.html not found. Place it next to server.js.');
    }
  });
});

app.get('/health', async (req, res) => {
  try {
    if (pool) await pool.query('SELECT 1');

    res.json({
      status: 'ok',
      version: VERSION,
      storage: pool ? 'postgres' : 'memory',
      persistent: Boolean(pool)
    });
  } catch {
    res.status(503).json({
      status: 'error',
      message: 'Database unavailable.'
    });
  }
});

app.get('/api/status', async (req, res, next) => {
  try {
    res.json(await makeStatus());
  } catch (error) {
    next(error);
  }
});

app.get('/api/economy', async (req, res, next) => {
  try {
    const supply = await currentSupply();

    res.json({
      totalSupply: supply,
      total_supply: supply,
      supply,
      circulatingSupply: supply,
      circulating_supply: supply,
      maxSupply: MAX_SUPPLY,
      max_supply: MAX_SUPPLY,
      transferFee: FEE,
      transfer_fee: FEE,
      faucetAmount: FAUCET_AMOUNT,
      network: NETWORK,
      version: VERSION
    });
  } catch (error) {
    next(error);
  }
});

app.get('/api/blocks', async (req, res, next) => {
  try {
    res.json({ blocks: await getBlocks(50) });
  } catch (error) {
    next(error);
  }
});

// Supports both the current frontend's GET request and older POST clients.
app.route('/api/chain/verify')
  .get(authenticate, async (req, res, next) => {
    try {
      res.json(await getChainVerification());
    } catch (error) {
      next(error);
    }
  })
  .post(authenticate, async (req, res, next) => {
    try {
      res.json(await getChainVerification());
    } catch (error) {
      next(error);
    }
  });

// Authentication.
app.post('/api/auth/register', async (req, res, next) => {
  try {
    const username = validateUsername(req.body?.username);
    const password = validatePassword(req.body?.password);
    const passwordHash = await bcrypt.hash(password, 12);
    const recoveryCode = createRecoveryCode();
    const recoveryHash = await bcrypt.hash(recoveryCode, 12);

    const result = await withMutation(async client => {
      const duplicate = await client.query(
        'SELECT id FROM users WHERE LOWER(username) = LOWER($1) LIMIT 1',
        [username]
      );

      if (duplicate.rows.length) {
        fail(409, 'Такое имя пользователя уже занято.');
      }

      const columns = [
        'username',
        'password_hash',
        'recovery_code',
        'recovery_hash',
        'created_at'
      ];

      const values = [
        username,
        passwordHash,
        recoveryHash,
        recoveryHash,
        new Date()
      ];

      // Earlier schemas may have a required `password` column.
      if (dbUserColumns.has('password')) {
        columns.push('password');
        values.push(passwordHash);
      }

      const placeholders = values.map((_, index) => `$${index + 1}`).join(', ');

      const userResult = await client.query(
        `INSERT INTO users (${columns.join(', ')})
         VALUES (${placeholders})
         RETURNING id, username, created_at`,
        values
      );

      const user = userResult.rows[0];
      const wallet = await createPgWallet(client, user.id);

      await addPgBlock(client, 0, {
        event: 'REGISTER',
        userId: String(user.id),
        walletAddress: wallet.address
      });

      return { user, wallet };
    }, async () => {
      if (memory.users.some(user => user.username === username)) {
        fail(409, 'Такое имя пользователя уже занято.');
      }

      const user = {
        id: memory.nextUserId++,
        username,
        password_hash: passwordHash,
        recovery_hash: recoveryHash,
        recovery_code: recoveryHash,
        created_at: new Date().toISOString()
      };

      memory.users.push(user);

      const wallet = createMemoryWallet(user.id);

      addMemoryBlock(0, {
        event: 'REGISTER',
        userId: String(user.id),
        walletAddress: wallet.address
      });

      return { user, wallet };
    });

    const token = signToken(result.user);

    res.status(201).json({
      token,
      accessToken: token,
      recoveryCode,
      recovery_code: recoveryCode,
      user: publicUser(result.user),
      wallet: publicWallet(result.wallet)
    });
  } catch (error) {
    next(error);
  }
});

app.post('/api/auth/login', async (req, res, next) => {
  try {
    const username = normalizeUsername(req.body?.username);
    const password = req.body?.password;

    if (!username || typeof password !== 'string' || !password) {
      fail(400, 'Введи имя пользователя и пароль.');
    }

    const user = pool
      ? (await pool.query(
          `SELECT id, username, password_hash, recovery_hash, recovery_code, created_at
           FROM users
           WHERE LOWER(username) = LOWER($1)
           LIMIT 1`,
          [username]
        )).rows[0]
      : memory.users.find(item => item.username === username);

    if (!user) {
      fail(401, 'Неверное имя пользователя или пароль.');
    }

    let passwordOk = false;

    try {
      passwordOk = await bcrypt.compare(password, String(user.password_hash || ''));
    } catch {}

    // Upgrade legacy plaintext password records if any still exist.
    if (
      !passwordOk &&
      user.password_hash &&
      !String(user.password_hash).startsWith('$2') &&
      user.password_hash === password
    ) {
      passwordOk = true;
      const upgraded = await bcrypt.hash(password, 12);

      if (pool) {
        await pool.query(
          'UPDATE users SET password_hash = $1 WHERE id = $2',
          [upgraded, user.id]
        );

        if (dbUserColumns.has('password')) {
          await pool.query(
            'UPDATE users SET password = $1 WHERE id = $2',
            [upgraded, user.id]
          );
        }
      } else {
        user.password_hash = upgraded;
      }
    }

    if (!passwordOk) {
      fail(401, 'Неверное имя пользователя или пароль.');
    }

    const token = signToken(user);

    res.json({
      token,
      accessToken: token,
      user: publicUser(user)
    });
  } catch (error) {
    next(error);
  }
});

app.get('/api/auth/me', authenticate, (req, res) => {
  res.json({
    user: publicUser(req.user),
    me: publicUser(req.user)
  });
});

app.post('/api/auth/password/change', authenticate, async (req, res, next) => {
  try {
    const currentPassword = req.body?.currentPassword;
    const newPassword = validatePassword(req.body?.newPassword);

    let matches = false;

    try {
      matches = await bcrypt.compare(
        String(currentPassword || ''),
        String(req.user.password_hash || '')
      );
    } catch {}

    if (
      !matches &&
      req.user.password_hash &&
      !String(req.user.password_hash).startsWith('$2')
    ) {
      matches = req.user.password_hash === currentPassword;
    }

    if (!matches) {
      fail(400, 'Текущий пароль указан неверно.');
    }

    const passwordHash = await bcrypt.hash(newPassword, 12);

    if (pool) {
      await pool.query(
        'UPDATE users SET password_hash = $1 WHERE id = $2',
        [passwordHash, req.user.id]
      );

      if (dbUserColumns.has('password')) {
        await pool.query(
          'UPDATE users SET password = $1 WHERE id = $2',
          [passwordHash, req.user.id]
        );
      }
    } else {
      req.user.password_hash = passwordHash;
    }

    const updated = {
      ...req.user,
      password_hash: passwordHash
    };

    res.json({
      ok: true,
      token: signToken(updated),
      user: publicUser(updated)
    });
  } catch (error) {
    next(error);
  }
});

app.post('/api/auth/recovery/reset', async (req, res, next) => {
  try {
    const username = normalizeUsername(req.body?.username);
    const recoveryCode = normalizeRecoveryCode(
      req.body?.recoveryCode || req.body?.recovery_code
    );
    const newPassword = validatePassword(req.body?.newPassword);

    if (!username || !recoveryCode) {
      fail(400, 'Введи имя пользователя и код восстановления.');
    }

    const user = pool
      ? (await pool.query(
          `SELECT id, username, password_hash, recovery_hash, recovery_code, created_at
           FROM users
           WHERE LOWER(username) = LOWER($1)
           LIMIT 1`,
          [username]
        )).rows[0]
      : memory.users.find(item => item.username === username);

    if (!user) {
      fail(400, 'Неверное имя пользователя или код восстановления.');
    }

    let recoveryOk = false;

    for (const savedCode of [user.recovery_hash, user.recovery_code]) {
      if (!savedCode) continue;

      try {
        if (await bcrypt.compare(recoveryCode, String(savedCode))) {
          recoveryOk = true;
        }
      } catch {}

      // Support recovery codes created by earlier versions that stored them plainly.
      if (!recoveryOk && String(savedCode).toUpperCase() === recoveryCode) {
        recoveryOk = true;
      }
    }

    if (!recoveryOk) {
      fail(400, 'Неверное имя пользователя или код восстановления.');
    }

    const passwordHash = await bcrypt.hash(newPassword, 12);
    const recoveryHash = await bcrypt.hash(recoveryCode, 12);
    const token = signToken({ ...user, password_hash: passwordHash });

    if (pool) {
      await pool.query(
        `UPDATE users
         SET password_hash = $1, recovery_hash = $2, recovery_code = $2
         WHERE id = $3`,
        [passwordHash, recoveryHash, user.id]
      );

      if (dbUserColumns.has('password')) {
        await pool.query(
          'UPDATE users SET password = $1 WHERE id = $2',
          [passwordHash, user.id]
        );
      }
    } else {
      user.password_hash = passwordHash;
      user.recovery_hash = recoveryHash;
      user.recovery_code = recoveryHash;
    }

    res.json({
      ok: true,
      token,
      accessToken: token,
      user: publicUser({ ...user, password_hash: passwordHash })
    });
  } catch (error) {
    next(error);
  }
});

app.post('/api/auth/logout', authenticate, (req, res) => {
  // The frontend clears the bearer token. Tokens expire after seven days.
  res.json({ ok: true });
});

// Wallets.
app.get('/api/wallets', authenticate, async (req, res, next) => {
  try {
    res.json({ wallets: await getWalletRowsForUser(req.user.id) });
  } catch (error) {
    next(error);
  }
});

app.post('/api/wallet/create', authenticate, async (req, res, next) => {
  try {
    const wallet = await withMutation(async client => {
      const created = await createPgWallet(client, req.user.id);

      await addPgBlock(client, 0, {
        event: 'WALLET_CREATE',
        userId: String(req.user.id),
        walletAddress: created.address
      });

      return created;
    }, async () => {
      const created = createMemoryWallet(req.user.id);

      addMemoryBlock(0, {
        event: 'WALLET_CREATE',
        userId: String(req.user.id),
        walletAddress: created.address
      });

      return created;
    });

    res.status(201).json({ wallet: publicWallet(wallet) });
  } catch (error) {
    next(error);
  }
});

app.post('/api/wallet/select', authenticate, async (req, res, next) => {
  try {
    const walletId = req.body?.walletId ?? req.body?.wallet_id;

    if (walletId === undefined || walletId === null || walletId === '') {
      fail(400, 'Не выбран кошелёк.');
    }

    const wallet = await getWalletForUser(walletId, req.user.id);

    if (!wallet) {
      fail(404, 'Кошелёк не найден.');
    }

    res.json({ wallet: publicWallet(wallet) });
  } catch (error) {
    next(error);
  }
});

app.get('/api/wallet/:id', authenticate, async (req, res, next) => {
  try {
    const wallet = await getWalletForUser(req.params.id, req.user.id);

    if (!wallet) {
      fail(404, 'Кошелёк не найден.');
    }

    const transactions = await getWalletTransactions(wallet);

    res.json({
      wallet: publicWallet(wallet),
      transactions,
      history: transactions
    });
  } catch (error) {
    next(error);
  }
});

// Testnet faucet: one claim per account every 24 hours.
app.post('/api/faucet', authenticate, async (req, res, next) => {
  try {
    const walletId = req.body?.walletId ?? req.body?.wallet_id;

    if (walletId === undefined || walletId === null || walletId === '') {
      fail(400, 'Выбери кошелёк.');
    }

    const result = await withMutation(async client => {
      const wallet = await getWalletForUser(walletId, req.user.id, client);

      if (!wallet) {
        fail(404, 'Кошелёк не найден.');
      }

      const lastClaim = await client.query(
        `SELECT claimed_at
         FROM faucet_claims
         WHERE user_id = $1
         ORDER BY claimed_at DESC
         LIMIT 1`,
        [req.user.id]
      );

      if (lastClaim.rows.length) {
        const elapsed = Date.now() - new Date(lastClaim.rows[0].claimed_at).getTime();

        if (elapsed < FAUCET_COOLDOWN_MS) {
          const waitSeconds = Math.ceil((FAUCET_COOLDOWN_MS - elapsed) / 1000);
          fail(429, `Faucet уже использован. Попробуй через ${Math.ceil(waitSeconds / 3600)} ч.`);
        }
      }

      const supply = await currentSupply(client);

      if (supply + FAUCET_AMOUNT > MAX_SUPPLY) {
        fail(409, 'Достигнут максимальный объём тестовых SLX.');
      }

      await client.query(
        'UPDATE wallets SET balance = balance + $1::numeric WHERE id = $2 AND user_id = $3',
        [FAUCET_AMOUNT, walletId, req.user.id]
      );

      await client.query(
        `INSERT INTO faucet_claims (user_id, wallet_id, claimed_at, created_at)
         VALUES ($1, $2, NOW(), NOW())`,
        [req.user.id, walletId]
      );

      const tx = await addPgTransaction(client, {
        from_wallet: 'FAUCET',
        to_wallet: wallet.address,
        amountUnits: amountToUnits(FAUCET_AMOUNT),
        feeUnits: 0,
        type: 'FAUCET'
      });

      await addPgBlock(client, 1, {
        event: 'FAUCET',
        txHash: tx.tx_hash || tx.hash,
        wallet: wallet.address,
        amount: FAUCET_AMOUNT
      });

      return {
        amount: FAUCET_AMOUNT,
        address: wallet.address
      };
    }, async () => {
      const wallet = await getWalletForUser(walletId, req.user.id);

      if (!wallet) {
        fail(404, 'Кошелёк не найден.');
      }

      const previousClaim = memory.faucetClaims
        .filter(claim => String(claim.user_id) === String(req.user.id))
        .sort((a, b) => new Date(b.claimed_at) - new Date(a.claimed_at))[0];

      if (previousClaim) {
        const elapsed = Date.now() - new Date(previousClaim.claimed_at).getTime();

        if (elapsed < FAUCET_COOLDOWN_MS) {
          fail(
            429,
            `Faucet уже использован. Попробуй через ${Math.ceil((FAUCET_COOLDOWN_MS - elapsed) / 3_600_000)} ч.`
          );
        }
      }

      const supply = await currentSupply();

      if (supply + FAUCET_AMOUNT > MAX_SUPPLY) {
        fail(409, 'Достигнут максимальный объём тестовых SLX.');
      }

      wallet.balance = unitsToAmount(
        dbAmountToUnits(wallet.balance) + amountToUnits(FAUCET_AMOUNT)
      );

      const now = new Date().toISOString();

      memory.faucetClaims.push({
        user_id: req.user.id,
        wallet_id: walletId,
        claimed_at: now
      });

      const tx = addMemoryTransaction({
        from_wallet: 'FAUCET',
        to_wallet: wallet.address,
        amountUnits: amountToUnits(FAUCET_AMOUNT),
        feeUnits: 0,
        type: 'FAUCET'
      });

      addMemoryBlock(1, {
        event: 'FAUCET',
        txHash: tx.tx_hash,
        wallet: wallet.address,
        amount: FAUCET_AMOUNT
      });

      return {
        amount: FAUCET_AMOUNT,
        address: wallet.address
      };
    });

    res.json({
      ok: true,
      amount: result.amount,
      address: result.address,
      cooldown: FAUCET_COOLDOWN_MS
    });
  } catch (error) {
    next(error);
  }
});

// SLX testnet transfer. Balance changes, transaction and block are committed atomically.
app.post('/api/send', authenticate, async (req, res, next) => {
  try {
    const fromWalletId = req.body?.fromWalletId ?? req.body?.from_wallet_id;
    const toAddress = validateAddress(
      req.body?.toAddress ?? req.body?.to_address ?? req.body?.to
    );
    const amountUnits = amountToUnits(req.body?.amount);
    const feeUnits = amountToUnits(FEE);

    if (fromWalletId === undefined || fromWalletId === null || fromWalletId === '') {
      fail(400, 'Не выбран кошелёк отправителя.');
    }

    const result = await withMutation(async client => {
      const sourceResult = await client.query(
        `SELECT id, user_id, address, balance, created_at
         FROM wallets
         WHERE id = $1 AND user_id = $2
         LIMIT 1
         FOR UPDATE`,
        [fromWalletId, req.user.id]
      );

      const source = sourceResult.rows[0];

      if (!source) {
        fail(404, 'Кошелёк отправителя не найден.');
      }

      if (source.address === toAddress) {
        fail(400, 'Нельзя отправить SLX на тот же адрес.');
      }

      const recipientResult = await client.query(
        `SELECT id, user_id, address, balance
         FROM wallets
         WHERE address = $1
         LIMIT 1
         FOR UPDATE`,
        [toAddress]
      );

      const recipient = recipientResult.rows[0];

      if (!recipient) {
        fail(404, 'Кошелёк получателя не найден в SLX Testnet.');
      }

      const sourceUnits = dbAmountToUnits(source.balance);

      if (sourceUnits < amountUnits + feeUnits) {
        fail(400, 'Недостаточно SLX с учётом комиссии.');
      }

      const recipientUnits = dbAmountToUnits(recipient.balance);

      await client.query(
        'UPDATE wallets SET balance = $1::numeric WHERE id = $2',
        [amountToDb(sourceUnits - amountUnits - feeUnits), source.id]
      );

      await client.query(
        'UPDATE wallets SET balance = $1::numeric WHERE id = $2',
        [amountToDb(recipientUnits + amountUnits), recipient.id]
      );

      const tx = await addPgTransaction(client, {
        from_wallet: source.address,
        to_wallet: recipient.address,
        amountUnits,
        feeUnits,
        type: 'SEND'
      });

      const txHash = tx.tx_hash || tx.hash;

      const block = await addPgBlock(client, 1, {
        event: 'SEND',
        txHash,
        from: source.address,
        to: recipient.address,
        amount: unitsToAmount(amountUnits),
        fee: unitsToAmount(feeUnits)
      });

      return {
        transaction: tx,
        block: publicBlock(block),
        fee: unitsToAmount(feeUnits)
      };
    }, async () => {
      const source = await getWalletForUser(fromWalletId, req.user.id);

      if (!source) {
        fail(404, 'Кошелёк отправителя не найден.');
      }

      if (source.address === toAddress) {
        fail(400, 'Нельзя отправить SLX на тот же адрес.');
      }

      const recipient = memory.wallets.find(wallet => wallet.address === toAddress);

      if (!recipient) {
        fail(404, 'Кошелёк получателя не найден в SLX Testnet.');
      }

      const sourceUnits = dbAmountToUnits(source.balance);

      if (sourceUnits < amountUnits + feeUnits) {
        fail(400, 'Недостаточно SLX с учётом комиссии.');
      }

      const recipientUnits = dbAmountToUnits(recipient.balance);

      source.balance = unitsToAmount(sourceUnits - amountUnits - feeUnits);
      recipient.balance = unitsToAmount(recipientUnits + amountUnits);

      const tx = addMemoryTransaction({
        from_wallet: source.address,
        to_wallet: recipient.address,
        amountUnits,
        feeUnits,
        type: 'SEND'
      });

      const block = addMemoryBlock(1, {
        event: 'SEND',
        txHash: tx.tx_hash,
        from: source.address,
        to: recipient.address,
        amount: unitsToAmount(amountUnits),
        fee: unitsToAmount(feeUnits)
      });

      return {
        transaction: tx,
        block: publicBlock(block),
        fee: unitsToAmount(feeUnits)
      };
    });

    res.json({
      ok: true,
      transaction: result.transaction,
      txHash: result.transaction.tx_hash || result.transaction.hash,
      block: result.block,
      fee: result.fee
    });
  } catch (error) {
    next(error);
  }
});

// API 404s return JSON for the frontend.
app.use('/api', (req, res) => {
  res.status(404).json({ message: 'API endpoint не найден.' });
});

app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);

  const status = Number(error.status) || 500;

  if (status >= 500) {
    console.error('[SLX] Server error:', error);
  }

  const message = status >= 500
    ? 'Внутренняя ошибка сервера. Проверь логи Render.'
    : (error.message || 'Запрос не выполнен.');

  res.status(status).json({
    message,
    error: message
  });
});

async function start() {
  await initDatabase();

  const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(
      `[SLX] Network ${VERSION} listening on port ${PORT} (${pool ? 'PostgreSQL' : 'memory mode'})`
    );
  });

  const shutdown = async signal => {
    console.log(`[SLX] ${signal} received; shutting down.`);

    server.close(async () => {
      if (pool) {
        await pool.end().catch(() => {});
      }

      process.exit(0);
    });

    setTimeout(() => process.exit(1), 10_000).unref();
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

start().catch(error => {
  console.error('[SLX] Startup failed:', error.message || error);
  process.exit(1);
});