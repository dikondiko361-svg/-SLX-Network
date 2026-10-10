'use strict';

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const crypto = require('crypto');
const path = require('path');

const app = express();

const PORT = Number(process.env.PORT || 10000);
const VERSION = '1.8.2';
const NETWORK_NAME = 'SLX-Testnet';

const JWT_SECRET =
  process.env.JWT_SECRET ||
  'SLX-Network-v1.8.2-Testnet-Change-This-Secret';

const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error('❌ DATABASE_URL is not set');
  process.exit(1);
}

/* =========================================================
   DATABASE
========================================================= */

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl:
    process.env.NODE_ENV === 'production'
      ? { rejectUnauthorized: false }
      : false,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

pool.on('error', (err) => {
  console.error('PostgreSQL pool error:', err);
});

/* =========================================================
   EXPRESS
========================================================= */

app.use(
  cors({
    origin: true,
    credentials: false
  })
);

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

/* =========================================================
   CONSTANTS
========================================================= */

const TRANSFER_FEE = 0.1;
const FAUCET_AMOUNT = 10;
const FAUCET_COOLDOWN_MS = 24 * 60 * 60 * 1000;

const WALLET_REGEX = /^SLXC[A-F0-9]{32}$/i;

/* =========================================================
   HELPERS
========================================================= */

function now() {
  return new Date();
}

function generateWalletAddress() {
  return (
    'SLXC' +
    crypto.randomBytes(16).toString('hex').toUpperCase()
  );
}

function generateRecoveryCode() {
  return crypto.randomBytes(6).toString('hex').toUpperCase();
}

function generateTxHash() {
  return (
    'SLXTX' +
    crypto.randomBytes(20).toString('hex').toUpperCase()
  );
}

function generateBlockHash() {
  return (
    'SLXBLK' +
    crypto.randomBytes(24).toString('hex').toUpperCase()
  );
}

function signToken(user) {
  return jwt.sign(
    {
      sub: String(user.id),
      username: user.username
    },
    JWT_SECRET,
    {
      expiresIn: '30d'
    }
  );
}

function cleanUsername(value) {
  return String(value || '').trim();
}

function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    created_at: user.created_at
  };
}

function walletResponse(wallet) {
  return {
    id: wallet.id,
    user_id: wallet.user_id,
    name: wallet.name,
    address: wallet.address,
    balance: Number(wallet.balance || 0),
    created_at: wallet.created_at
  };
}

function transactionResponse(row) {
  return {
    id: row.id,
    tx_hash: row.tx_hash,
    type: row.type,
    from_wallet: row.from_wallet,
    to_wallet: row.to_wallet,
    amount: Number(row.amount || 0),
    fee: Number(row.fee || 0),
    created_at: row.created_at,
    block_id: row.block_id
  };
}

/* =========================================================
   AUTH MIDDLEWARE
========================================================= */

function authRequired(req, res, next) {
  try {
    const header = req.headers.authorization || '';

    if (!header.startsWith('Bearer ')) {
      return res.status(401).json({
        message: 'Unauthorized'
      });
    }

    const token = header.slice(7).trim();

    if (!token) {
      return res.status(401).json({
        message: 'Unauthorized'
      });
    }

    const decoded = jwt.verify(token, JWT_SECRET);

    req.user = {
      id: Number(decoded.sub),
      username: decoded.username
    };

    next();
  } catch (err) {
    return res.status(401).json({
      message: 'Invalid or expired token'
    });
  }
}

/* =========================================================
   DATABASE INIT
========================================================= */

async function initDatabase() {
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id BIGSERIAL PRIMARY KEY,
        username VARCHAR(64) NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        recovery_code_hash TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS wallets (
        id BIGSERIAL PRIMARY KEY,
        user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(100) NOT NULL DEFAULT 'Main Wallet',
        address VARCHAR(36) NOT NULL UNIQUE,
        balance NUMERIC(30,8) NOT NULL DEFAULT 0,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS blocks (
        id BIGSERIAL PRIMARY KEY,
        block_index BIGINT NOT NULL UNIQUE,
        timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        hash VARCHAR(128) NOT NULL UNIQUE,
        previous_hash VARCHAR(128),
        transaction_count INTEGER NOT NULL DEFAULT 0
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS transactions (
        id BIGSERIAL PRIMARY KEY,
        tx_hash VARCHAR(128) NOT NULL UNIQUE,
        type VARCHAR(32) NOT NULL,
        from_wallet VARCHAR(36),
        to_wallet VARCHAR(36),
        amount NUMERIC(30,8) NOT NULL DEFAULT 0,
        fee NUMERIC(30,8) NOT NULL DEFAULT 0,
        block_id BIGINT REFERENCES blocks(id) ON DELETE SET NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS faucet_claims (
        id BIGSERIAL PRIMARY KEY,
        wallet_id BIGINT NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
        claimed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_wallets_user_id
      ON wallets(user_id)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_transactions_from_wallet
      ON transactions(from_wallet)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_transactions_to_wallet
      ON transactions(to_wallet)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_transactions_created_at
      ON transactions(created_at DESC)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_faucet_wallet
      ON faucet_claims(wallet_id)
    `);

    const genesis = await client.query(`
      SELECT id
      FROM blocks
      WHERE block_index = 0
      LIMIT 1
    `);

    if (genesis.rowCount === 0) {
      await client.query(
        `
        INSERT INTO blocks (
          block_index,
          timestamp,
          hash,
          previous_hash,
          transaction_count
        )
        VALUES ($1, $2, $3, $4, $5)
        `,
        [
          0,
          now(),
          'SLX-GENESIS-V1.8.2',
          null,
          0
        ]
      );
    }

    await client.query('COMMIT');

    console.log('✅ Database initialized');
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('❌ Database initialization failed:', err);
    throw err;
  } finally {
    client.release();
  }
}

/* =========================================================
   BLOCK CREATION
========================================================= */

async function createBlock(client, transactionCount = 1) {
  const previousResult = await client.query(`
    SELECT
      block_index,
      hash
    FROM blocks
    ORDER BY block_index DESC
    LIMIT 1
  `);

  const previous =
    previousResult.rows[0] || {
      block_index: 0,
      hash: 'SLX-GENESIS-V1.8.2'
    };

  const nextIndex = Number(previous.block_index) + 1;
  const timestamp = now();

  const hash = generateBlockHash();

  const result = await client.query(
    `
    INSERT INTO blocks (
      block_index,
      timestamp,
      hash,
      previous_hash,
      transaction_count
    )
    VALUES ($1, $2, $3, $4, $5)
    RETURNING *
    `,
    [
      nextIndex,
      timestamp,
      hash,
      previous.hash,
      transactionCount
    ]
  );

  return result.rows[0];
}

/* =========================================================
   HEALTH
========================================================= */

app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');

    res.json({
      ok: true,
      status: 'online',
      version: VERSION,
      network: NETWORK_NAME
    });
  } catch (err) {
    res.status(503).json({
      ok: false,
      status: 'database_error',
      version: VERSION
    });
  }
});

/* =========================================================
   STATUS
========================================================= */

app.get('/api/status', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT COUNT(*)::int AS count
      FROM blocks
    `);

    const blockCount = Number(result.rows[0]?.count || 0);

    res.json({
      name: 'SLX Network',
      version: VERSION,
      network: NETWORK_NAME,
      status: 'online',
      message: 'SLX Network server is running',
      networkInfo: {
        name: NETWORK_NAME,
        version: VERSION,
        height: Math.max(0, blockCount - 1),
        transferFee: TRANSFER_FEE
      }
    });
  } catch (err) {
    console.error('STATUS ERROR:', err);

    res.status(500).json({
      message: 'Failed to load network status'
    });
  }
});

/* =========================================================
   REGISTER
========================================================= */

app.post('/api/auth/register', async (req, res) => {
  const username = cleanUsername(req.body.username);
  const password = String(req.body.password || '');

  if (!username) {
    return res.status(400).json({
      message: 'Username is required'
    });
  }

  if (username.length < 3 || username.length > 64) {
    return res.status(400).json({
      message: 'Username must contain 3-64 characters'
    });
  }

  if (!/^[A-Za-z0-9_.-]+$/.test(username)) {
    return res.status(400).json({
      message: 'Username contains invalid characters'
    });
  }

  if (password.length < 6) {
    return res.status(400).json({
      message: 'Password must contain at least 6 characters'
    });
  }

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const existing = await client.query(
      `
      SELECT id
      FROM users
      WHERE LOWER(username) = LOWER($1)
      LIMIT 1
      `,
      [username]
    );

    if (existing.rowCount > 0) {
      await client.query('ROLLBACK');

      return res.status(409).json({
        message: 'Username already exists'
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const recoveryCode = generateRecoveryCode();
    const recoveryHash = await bcrypt.hash(
      recoveryCode,
      12
    );

    const userResult = await client.query(
      `
      INSERT INTO users (
        username,
        password_hash,
        recovery_code_hash
      )
      VALUES ($1, $2, $3)
      RETURNING id, username, created_at
      `,
      [
        username,
        passwordHash,
        recoveryHash
      ]
    );

    const user = userResult.rows[0];

    const walletAddress = generateWalletAddress();

    const walletResult = await client.query(
      `
      INSERT INTO wallets (
        user_id,
        name,
        address,
        balance
      )
      VALUES ($1, $2, $3, $4)
      RETURNING *
      `,
      [
        user.id,
        'Main Wallet',
        walletAddress,
        0
      ]
    );

    const token = signToken(user);

    await client.query('COMMIT');

    console.log(
      `✅ Registered user: ${username}`
    );

    return res.status(201).json({
      ok: true,
      message: 'Registration successful',

      token,
      accessToken: token,

      recoveryCode,
      recovery_code: recoveryCode,

      user: publicUser(user),

      wallet: walletResponse(walletResult.rows[0])
    });
  } catch (err) {
    await client.query('ROLLBACK');

    console.error(
      'REGISTER ERROR:',
      err
    );

    if (err.code === '23505') {
      return res.status(409).json({
        message: 'Username or wallet already exists'
      });
    }

    return res.status(500).json({
      message: 'Registration failed',
      error:
        process.env.NODE_ENV === 'production'
          ? undefined
          : err.message
    });
  } finally {
    client.release();
  }
});

/* =========================================================
   LOGIN
========================================================= */

app.post('/api/auth/login', async (req, res) => {
  const username = cleanUsername(req.body.username);
  const password = String(req.body.password || '');

  if (!username || !password) {
    return res.status(400).json({
      message: 'Username and password are required'
    });
  }

  try {
    const result = await pool.query(
      `
      SELECT *
      FROM users
      WHERE LOWER(username) = LOWER($1)
      LIMIT 1
      `,
      [username]
    );

    if (result.rowCount === 0) {
      return res.status(401).json({
        message: 'Invalid username or password'
      });
    }

    const user = result.rows[0];

    const valid = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!valid) {
      return res.status(401).json({
        message: 'Invalid username or password'
      });
    }

    const token = signToken(user);

    return res.json({
      ok: true,
      token,
      accessToken: token,
      user: publicUser(user)
    });
  } catch (err) {
    console.error(
      'LOGIN ERROR:',
      err
    );

    return res.status(500).json({
      message: 'Login failed'
    });
  }
});

/* =========================================================
   ME
========================================================= */

app.get(
  '/api/auth/me',
  authRequired,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT id, username, created_at
        FROM users
        WHERE id = $1
        LIMIT 1
        `,
        [req.user.id]
      );

      if (result.rowCount === 0) {
        return res.status(404).json({
          message: 'User not found'
        });
      }

      res.json({
        ok: true,
        user: publicUser(result.rows[0])
      });
    } catch (err) {
      console.error(
        'ME ERROR:',
        err
      );

      res.status(500).json({
        message: 'Failed to load user'
      });
    }
  }
);

/* =========================================================
   RECOVERY RESET
========================================================= */

app.post(
  '/api/auth/recovery/reset',
  async (req, res) => {
    const username = cleanUsername(
      req.body.username
    );

    const recoveryCode = String(
      req.body.recoveryCode ||
      req.body.recovery_code ||
      ''
    )
      .trim()
      .toUpperCase();

    const newPassword = String(
      req.body.newPassword ||
      ''
    );

    if (
      !username ||
      !recoveryCode ||
      !newPassword
    ) {
      return res.status(400).json({
        message: 'Invalid recovery data'
      });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({
        message:
          'New password must contain at least 6 characters'
      });
    }

    try {
      const result = await pool.query(
        `
        SELECT *
        FROM users
        WHERE LOWER(username) = LOWER($1)
        LIMIT 1
        `,
        [username]
      );

      if (result.rowCount === 0) {
        return res.status(400).json({
          message: 'Invalid recovery data'
        });
      }

      const user = result.rows[0];

      const validRecovery =
        await bcrypt.compare(
          recoveryCode,
          user.recovery_code_hash
        );

      if (!validRecovery) {
        return res.status(400).json({
          message: 'Invalid recovery data'
        });
      }

      const newHash = await bcrypt.hash(
        newPassword,
        12
      );

      await pool.query(
        `
        UPDATE users
        SET password_hash = $1
        WHERE id = $2
        `,
        [
          newHash,
          user.id
        ]
      );

      const token = signToken(user);

      return res.json({
        ok: true,
        message: 'Password reset successful',
        token,
        accessToken: token,
        user: publicUser(user)
      });
    } catch (err) {
      console.error(
        'RECOVERY ERROR:',
        err
      );

      return res.status(500).json({
        message: 'Recovery failed'
      });
    }
  }
);

/* =========================================================
   CHANGE PASSWORD
========================================================= */

app.post(
  '/api/auth/password/change',
  authRequired,
  async (req, res) => {
    const currentPassword = String(
      req.body.currentPassword || ''
    );

    const newPassword = String(
      req.body.newPassword || ''
    );

    if (
      !currentPassword ||
      !newPassword
    ) {
      return res.status(400).json({
        message: 'Password fields are required'
      });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({
        message:
          'New password must contain at least 6 characters'
      });
    }

    try {
      const result = await pool.query(
        `
        SELECT *
        FROM users
        WHERE id = $1
        LIMIT 1
        `,
        [req.user.id]
      );

      if (result.rowCount === 0) {
        return res.status(404).json({
          message: 'User not found'
        });
      }

      const user = result.rows[0];

      const valid =
        await bcrypt.compare(
          currentPassword,
          user.password_hash
        );

      if (!valid) {
        return res.status(400).json({
          message: 'Current password is incorrect'
        });
      }

      const newHash = await bcrypt.hash(
        newPassword,
        12
      );

      await pool.query(
        `
        UPDATE users
        SET password_hash = $1
        WHERE id = $2
        `,
        [
          newHash,
          user.id
        ]
      );

      const token = signToken(user);

      return res.json({
        ok: true,
        message: 'Password changed',
        token,
        accessToken: token
      });
    } catch (err) {
      console.error(
        'PASSWORD CHANGE ERROR:',
        err
      );

      res.status(500).json({
        message: 'Password change failed'
      });
    }
  }
);

/* =========================================================
   LOGOUT
========================================================= */

app.post(
  '/api/auth/logout',
  authRequired,
  async (req, res) => {
    res.json({
      ok: true,
      message: 'Logged out'
    });
  }
);

/* =========================================================
   GET WALLETS
========================================================= */

app.get(
  '/api/wallets',
  authRequired,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT *
        FROM wallets
        WHERE user_id = $1
        ORDER BY id ASC
        `,
        [req.user.id]
      );

      res.json({
        ok: true,
        wallets:
          result.rows.map(walletResponse)
      });
    } catch (err) {
      console.error(
        'WALLETS ERROR:',
        err
      );

      res.status(500).json({
        message: 'Failed to load wallets'
      });
    }
  }
);

/* =========================================================
   CREATE WALLET
========================================================= */

app.post(
  '/api/wallet/create',
  authRequired,
  async (req, res) => {
    try {
      const countResult = await pool.query(
        `
        SELECT COUNT(*)::int AS count
        FROM wallets
        WHERE user_id = $1
        `,
        [req.user.id]
      );

      const number =
        Number(countResult.rows[0].count || 0) + 1;

      const address = generateWalletAddress();

      const result = await pool.query(
        `
        INSERT INTO wallets (
          user_id,
          name,
          address,
          balance
        )
        VALUES ($1, $2, $3, $4)
        RETURNING *
        `,
        [
          req.user.id,
          `Wallet ${number}`,
          address,
          0
        ]
      );

      res.status(201).json({
        ok: true,
        wallet: walletResponse(result.rows[0])
      });
    } catch (err) {
      console.error(
        'CREATE WALLET ERROR:',
        err
      );

      res.status(500).json({
        message: 'Failed to create wallet'
      });
    }
  }
);

/* =========================================================
   SELECT WALLET
========================================================= */

app.post(
  '/api/wallet/select',
  authRequired,
  async (req, res) => {
    const walletId = Number(
      req.body.walletId
    );

    if (!Number.isInteger(walletId)) {
      return res.status(400).json({
        message: 'Invalid wallet ID'
      });
    }

    try {
      const result = await pool.query(
        `
        SELECT *
        FROM wallets
        WHERE id = $1
          AND user_id = $2
        LIMIT 1
        `,
        [
          walletId,
          req.user.id
        ]
      );

      if (result.rowCount === 0) {
        return res.status(404).json({
          message: 'Wallet not found'
        });
      }

      res.json({
        ok: true,
        wallet: walletResponse(
          result.rows[0]
        )
      });
    } catch (err) {
      console.error(
        'SELECT WALLET ERROR:',
        err
      );

      res.status(500).json({
        message: 'Failed to select wallet'
      });
    }
  }
);

/* =========================================================
   WALLET DETAILS + TRANSACTIONS
========================================================= */

app.get(
  '/api/wallet/:id',
  authRequired,
  async (req, res) => {
    const walletId = Number(
      req.params.id
    );

    if (!Number.isInteger(walletId)) {
      return res.status(400).json({
        message: 'Invalid wallet ID'
      });
    }

    try {
      const walletResult = await pool.query(
        `
        SELECT *
        FROM wallets
        WHERE id = $1
          AND user_id = $2
        LIMIT 1
        `,
        [
          walletId,
          req.user.id
        ]
      );

      if (walletResult.rowCount === 0) {
        return res.status(404).json({
          message: 'Wallet not found'
        });
      }

      const wallet =
        walletResult.rows[0];

      const txResult = await pool.query(
        `
        SELECT *
        FROM transactions
        WHERE from_wallet = $1
           OR to_wallet = $1
        ORDER BY created_at DESC
        LIMIT 100
        `,
        [wallet.address]
      );

      res.json({
        ...walletResponse(wallet),
        transactions:
          txResult.rows.map(transactionResponse)
      });
    } catch (err) {
      console.error(
        'WALLET DETAILS ERROR:',
        err
      );

      res.status(500).json({
        message: 'Failed to load wallet'
      });
    }
  }
);

/* =========================================================
   FAUCET
========================================================= */

app.post(
  '/api/faucet',
  authRequired,
  async (req, res) => {
    const walletId = Number(
      req.body.walletId
    );

    if (!Number.isInteger(walletId)) {
      return res.status(400).json({
        message: 'Invalid wallet ID'
      });
    }

    const client = await pool.connect();

    try {
      await client.query('BEGIN');

      const walletResult = await client.query(
        `
        SELECT *
        FROM wallets
        WHERE id = $1
          AND user_id = $2
        FOR UPDATE
        `,
        [
          walletId,
          req.user.id
        ]
      );

      if (walletResult.rowCount === 0) {
        await client.query('ROLLBACK');

        return res.status(404).json({
          message: 'Wallet not found'
        });
      }

      const wallet =
        walletResult.rows[0];

      const claimResult = await client.query(
        `
        SELECT claimed_at
        FROM faucet_claims
        WHERE wallet_id = $1
        ORDER BY claimed_at DESC
        LIMIT 1
        `,
        [wallet.id]
      );

      if (claimResult.rowCount > 0) {
        const lastClaim =
          new Date(
            claimResult.rows[0].claimed_at
          ).getTime();

        const elapsed =
          Date.now() - lastClaim;

        if (
          elapsed <
          FAUCET_COOLDOWN_MS
        ) {
          const remaining =
            Math.ceil(
              (FAUCET_COOLDOWN_MS - elapsed) /
                1000
            );

          await client.query('ROLLBACK');

          return res.status(429).json({
            message:
              `Faucet cooldown active. Try again in ${remaining} seconds.`
          });
        }
      }

      const txHash =
        generateTxHash();

      const block =
        await createBlock(
          client,
          1
        );

      const txResult = await client.query(
        `
        INSERT INTO transactions (
          tx_hash,
          type,
          from_wallet,
          to_wallet,
          amount,
          fee,
          block_id
        )
        VALUES (
          $1,
          $2,
          $3,
          $4,
          $5,
          $6,
          $7
        )
        RETURNING *
        `,
        [
          txHash,
          'FAUCET',
          null,
          wallet.address,
          FAUCET_AMOUNT,
          0,
          block.id
        ]
      );

      await client.query(
        `
        UPDATE wallets
        SET balance = balance + $1
        WHERE id = $2
        `,
        [
          FAUCET_AMOUNT,
          wallet.id
        ]
      );

      await client.query(
        `
        INSERT INTO faucet_claims (
          wallet_id
        )
        VALUES ($1)
        `,
        [wallet.id]
      );

      await client.query('COMMIT');

      const newBalance =
        Number(wallet.balance) +
        FAUCET_AMOUNT;

      res.json({
        ok: true,
        message: `Received ${FAUCET_AMOUNT} SLX`,
        amount: FAUCET_AMOUNT,
        balance: newBalance,
        transaction:
          transactionResponse(
            txResult.rows[0]
          ),
        block
      });
    } catch (err) {
      await client.query('ROLLBACK');

      console.error(
        'FAUCET ERROR:',
        err
      );

      res.status(500).json({
        message: 'Faucet failed'
      });
    } finally {
      client.release();
    }
  }
);

/* =========================================================
   SEND
========================================================= */

app.post(
  '/api/send',
  authRequired,
  async (req, res) => {
    const fromWalletId = Number(
      req.body.fromWalletId
    );

    const toAddress = String(
      req.body.toAddress || ''
    )
      .trim()
      .toUpperCase();

    const amount = Number(
      req.body.amount
    );

    if (!Number.isInteger(fromWalletId)) {
      return res.status(400).json({
        message: 'Invalid sender wallet'
      });
    }

    if (!WALLET_REGEX.test(toAddress)) {
      return res.status(400).json({
        message: 'Invalid SLX address'
      });
    }

    if (
      !Number.isFinite(amount) ||
      amount <= 0
    ) {
      return res.status(400).json({
        message: 'Invalid amount'
      });
    }

    const client = await pool.connect();

    try {
      await client.query('BEGIN');

      const senderResult =
        await client.query(
          `
          SELECT *
          FROM wallets
          WHERE id = $1
            AND user_id = $2
          FOR UPDATE
          `,
          [
            fromWalletId,
            req.user.id
          ]
        );

      if (senderResult.rowCount === 0) {
        await client.query('ROLLBACK');

        return res.status(404).json({
          message:
            'Sender wallet not found'
        });
      }

      const sender =
        senderResult.rows[0];

      if (
        sender.address === toAddress
      ) {
        await client.query('ROLLBACK');

        return res.status(400).json({
          message:
            'Cannot send to the same wallet'
        });
      }

      const recipientResult =
        await client.query(
          `
          SELECT *
          FROM wallets
          WHERE address = $1
          FOR UPDATE
          `,
          [toAddress]
        );

      if (recipientResult.rowCount === 0) {
        await client.query('ROLLBACK');

        return res.status(404).json({
          message:
            'Recipient wallet not found'
        });
      }

      const recipient =
        recipientResult.rows[0];

      const totalCost =
        amount + TRANSFER_FEE;

      const senderBalance =
        Number(sender.balance);

      if (
        senderBalance < totalCost
      ) {
        await client.query('ROLLBACK');

        return res.status(400).json({
          message:
            `Insufficient balance. Required ${totalCost} SLX.`
        });
      }

      const txHash =
        generateTxHash();

      const block =
        await createBlock(
          client,
          1
        );

      const txResult =
        await client.query(
          `
          INSERT INTO transactions (
            tx_hash,
            type,
            from_wallet,
            to_wallet,
            amount,
            fee,
            block_id
          )
          VALUES (
            $1,
            $2,
            $3,
            $4,
            $5,
            $6,
            $7
          )
          RETURNING *
          `,
          [
            txHash,
            'TRANSFER',
            sender.address,
            recipient.address,
            amount,
            TRANSFER_FEE,
            block.id
          ]
        );

      await client.query(
        `
        UPDATE wallets
        SET balance = balance - $1
        WHERE id = $2
        `,
        [
          totalCost,
          sender.id
        ]
      );

      await client.query(
        `
        UPDATE wallets
        SET balance = balance + $1
        WHERE id = $2
        `,
        [
          amount,
          recipient.id
        ]
      );

      await client.query('COMMIT');

      res.json({
        ok: true,
        message: 'Transaction successful',
        transaction:
          transactionResponse(
            txResult.rows[0]
          ),
        block,
        fee: TRANSFER_FEE,
        balance:
          senderBalance -
          totalCost
      });
    } catch (err) {
      await client.query('ROLLBACK');

      console.error(
        'SEND ERROR:',
        err
      );

      res.status(500).json({
        message: 'Transaction failed'
      });
    } finally {
      client.release();
    }
  }
);

/* =========================================================
   ECONOMY
========================================================= */

app.get(
  '/api/economy',
  authRequired,
  async (req, res) => {
    try {
      const result = await pool.query(`
        SELECT
          COALESCE(
            SUM(balance),
            0
          ) AS supply
        FROM wallets
      `);

      const supply =
        Number(
          result.rows[0]?.supply || 0
        );

      res.json({
        ok: true,

        totalSupply: supply,
        supply,

        maxSupply: 1000000000,
        max_supply: 1000000000,

        transferFee: TRANSFER_FEE,
        transfer_fee: TRANSFER_FEE,

        faucetAmount: FAUCET_AMOUNT
      });
    } catch (err) {
      console.error(
        'ECONOMY ERROR:',
        err
      );

      res.status(500).json({
        message:
          'Failed to load economy'
      });
    }
  }
);

/* =========================================================
   BLOCKS
========================================================= */

app.get(
  '/api/blocks',
  authRequired,
  async (req, res) => {
    try {
      const result = await pool.query(`
        SELECT
          id,
          block_index,
          timestamp,
          hash,
          previous_hash,
          transaction_count
        FROM blocks
        ORDER BY block_index DESC
        LIMIT 20
      `);

      res.json({
        ok: true,
        blocks: result.rows.map(
          (block) => ({
            id: block.id,
            block_index:
              Number(block.block_index),
            timestamp:
              block.timestamp,
            hash: block.hash,
            previous_hash:
              block.previous_hash,
            transaction_count:
              Number(
                block.transaction_count
              )
          })
        )
      });
    } catch (err) {
      console.error(
        'BLOCKS ERROR:',
        err
      );

      res.status(500).json({
        message:
          'Failed to load blocks'
      });
    }
  }
);

/* =========================================================
   CHAIN VERIFY
========================================================= */

async function verifyChain() {
  const result = await pool.query(`
    SELECT
      block_index,
      hash,
      previous_hash
    FROM blocks
    ORDER BY block_index ASC
  `);

  const blocks = result.rows;

  if (blocks.length === 0) {
    return false;
  }

  if (
    Number(blocks[0].block_index) !== 0
  ) {
    return false;
  }

  for (let i = 1; i < blocks.length; i++) {
    const previous =
      blocks[i - 1];

    const current =
      blocks[i];

    if (
      Number(current.block_index) !==
      Number(previous.block_index) + 1
    ) {
      return false;
    }

    if (
      current.previous_hash !==
      previous.hash
    ) {
      return false;
    }
  }

  return true;
}

app.post(
  '/api/chain/verify',
  authRequired,
  async (req, res) => {
    try {
      const valid =
        await verifyChain();

      res.json({
        ok: true,
        valid,
        verified: valid,
        status:
          valid
            ? 'valid'
            : 'invalid'
      });
    } catch (err) {
      console.error(
        'CHAIN VERIFY ERROR:',
        err
      );

      res.status(500).json({
        message:
          'Chain verification failed'
      });
    }
  }
);

app.get(
  '/api/chain/verify',
  authRequired,
  async (req, res) => {
    try {
      const valid =
        await verifyChain();

      res.json({
        ok: true,
        valid,
        verified: valid,
        status:
          valid
            ? 'valid'
            : 'invalid'
      });
    } catch (err) {
      console.error(
        'CHAIN VERIFY ERROR:',
        err
      );

      res.status(500).json({
        message:
          'Chain verification failed'
      });
    }
  }
);

/* =========================================================
   404 API
========================================================= */

app.use('/api', (req, res) => {
  res.status(404).json({
    message: 'API endpoint not found'
  });
});

/* =========================================================
   FRONTEND
========================================================= */

app.use(
  express.static(
    path.join(__dirname)
  )
);

app.get('*', (req, res) => {
  res.sendFile(
    path.join(
      __dirname,
      'index.html'
    )
  );
});

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
  (err, req, res, next) => {
    console.error(
      'UNHANDLED ERROR:',
      err
    );

    res.status(500).json({
      message: 'Internal server error'
    });
  }
);

/* =========================================================
   START SERVER
========================================================= */

async function startServer() {
  try {
    console.log('');
    console.log('================================');
    console.log('     SLX NETWORK v1.8.2');
    console.log('================================');
    console.log(
      `Network: ${NETWORK_NAME}`
    );
    console.log(
      `Port: ${PORT}`
    );

    await initDatabase();

    app.listen(
      PORT,
      '0.0.0.0',
      () => {
        console.log('');
        console.log(
          `✅ SLX Network v${VERSION} is running`
        );
        console.log(
          `🌐 Port: ${PORT}`
        );
        console.log(
          `⛓️ Network: ${NETWORK_NAME}`
        );
        console.log(
          `💰 Transfer fee: ${TRANSFER_FEE} SLX`
        );
        console.log(
          `🚰 Faucet: ${FAUCET_AMOUNT} SLX`
        );
        console.log('');
      }
    );
  } catch (err) {
    console.error('');
    console.error(
      '❌ SERVER START FAILED'
    );
    console.error(err);
    console.error('');

    process.exit(1);
  }
}

startServer();