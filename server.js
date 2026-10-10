// ============================================================
// SLX NETWORK v1.8.2
// Testnet Backend
// Node.js 22+ / Express 5 / PostgreSQL
// ============================================================

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const path = require("path");
const { Pool } = require("pg");

const app = express();

// ============================================================
// CONFIG
// ============================================================

const PORT = process.env.PORT || 3000;

const VERSION = "1.8.2";
const NETWORK_NAME = "SLX-Testnet";

const JWT_SECRET =
  process.env.JWT_SECRET ||
  "SLX_TESTNET_DEV_SECRET_CHANGE_ME_182";

const TRANSFER_FEE = 0.1;
const FAUCET_AMOUNT = 10;
const FAUCET_COOLDOWN_HOURS = 24;

const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error("ERROR: DATABASE_URL is not configured.");
  console.error("Add PostgreSQL DATABASE_URL to Render Environment.");
}

// ============================================================
// DATABASE
// ============================================================

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl:
    process.env.NODE_ENV === "production"
      ? { rejectUnauthorized: false }
      : false,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

// ============================================================
// EXPRESS
// ============================================================

app.use(
  cors({
    origin: true,
    credentials: true,
  })
);

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

// Serve frontend
app.use(express.static(path.join(__dirname)));

// ============================================================
// HELPERS
// ============================================================

function generateWalletAddress() {
  return (
    "SLXC" +
    crypto.randomBytes(16).toString("hex").toUpperCase()
  );
}

function generateRecoveryCode() {
  return crypto
    .randomBytes(6)
    .toString("hex")
    .toUpperCase();
}

function generateTxHash() {
  return (
    "SLX" +
    crypto.randomBytes(24).toString("hex").toUpperCase()
  );
}

function generateBlockHash() {
  return (
    "SLXB" +
    crypto.randomBytes(28).toString("hex").toUpperCase()
  );
}

function isValidWalletAddress(address) {
  return /^SLXC[A-F0-9]{32}$/.test(
    String(address || "").trim().toUpperCase()
  );
}

function normalizeUsername(username) {
  return String(username || "").trim();
}

function normalizeAddress(address) {
  return String(address || "").trim().toUpperCase();
}

function signToken(user) {
  return jwt.sign(
    {
      userId: user.id,
      username: user.username,
    },
    JWT_SECRET,
    {
      expiresIn: "30d",
    }
  );
}

function getBearerToken(req) {
  const header = req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return null;
  }

  return header.substring(7).trim();
}

function roundAmount(value) {
  return Math.round(Number(value) * 100000000) / 100000000;
}

function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    created_at: user.created_at,
  };
}

// ============================================================
// AUTH MIDDLEWARE
// ============================================================

async function authRequired(req, res, next) {
  try {
    const token = getBearerToken(req);

    if (!token) {
      return res.status(401).json({
        error: "Unauthorized",
        message: "Bearer token required",
      });
    }

    const decoded = jwt.verify(token, JWT_SECRET);

    const result = await pool.query(
      `
      SELECT id, username, created_at
      FROM users
      WHERE id = $1
      LIMIT 1
      `,
      [decoded.userId]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        error: "Unauthorized",
        message: "User not found",
      });
    }

    req.user = result.rows[0];

    next();
  } catch (error) {
    console.error("AUTH ERROR:", error.message);

    return res.status(401).json({
      error: "Unauthorized",
      message: "Invalid or expired token",
    });
  }
}

// ============================================================
// DATABASE INIT
// ============================================================

async function initDatabase() {
  if (!DATABASE_URL) {
    throw new Error("DATABASE_URL is missing.");
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(64) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      recovery_code_hash TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS wallets (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      address VARCHAR(36) UNIQUE NOT NULL,
      name VARCHAR(100) NOT NULL DEFAULT 'SLX Wallet',
      balance NUMERIC(30,8) NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS transactions (
      id SERIAL PRIMARY KEY,
      tx_hash VARCHAR(100) UNIQUE NOT NULL,
      type VARCHAR(30) NOT NULL,
      from_wallet INTEGER REFERENCES wallets(id) ON DELETE SET NULL,
      to_wallet INTEGER REFERENCES wallets(id) ON DELETE SET NULL,
      amount NUMERIC(30,8) NOT NULL DEFAULT 0,
      fee NUMERIC(30,8) NOT NULL DEFAULT 0,
      block_id INTEGER,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS blocks (
      id SERIAL PRIMARY KEY,
      block_index INTEGER UNIQUE NOT NULL,
      timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      hash VARCHAR(120) UNIQUE NOT NULL,
      previous_hash VARCHAR(120),
      transaction_count INTEGER NOT NULL DEFAULT 0
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS faucet_claims (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      wallet_id INTEGER NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
      claimed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_wallets_user_id
    ON wallets(user_id);
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_transactions_from_wallet
    ON transactions(from_wallet);
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_transactions_to_wallet
    ON transactions(to_wallet);
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_blocks_index
    ON blocks(block_index);
  `);

  // Genesis block
  const genesis = await pool.query(`
    SELECT id
    FROM blocks
    WHERE block_index = 0
    LIMIT 1
  `);

  if (genesis.rows.length === 0) {
    await pool.query(
      `
      INSERT INTO blocks (
        block_index,
        timestamp,
        hash,
        previous_hash,
        transaction_count
      )
      VALUES (
        0,
        NOW(),
        $1,
        NULL,
        0
      )
      `,
      ["SLX_GENESIS_1.8.2"]
    );
  }

  console.log("Database initialized.");
}

// ============================================================
// BLOCK CREATION
// ============================================================

async function createBlock(client, transactionCount = 1) {
  const lastBlock = await client.query(`
    SELECT
      block_index,
      hash
    FROM blocks
    ORDER BY block_index DESC
    LIMIT 1
  `);

  let nextIndex = 1;
  let previousHash = null;

  if (lastBlock.rows.length > 0) {
    nextIndex = Number(lastBlock.rows[0].block_index) + 1;
    previousHash = lastBlock.rows[0].hash;
  }

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
    VALUES ($1, NOW(), $2, $3, $4)
    RETURNING *
    `,
    [
      nextIndex,
      hash,
      previousHash,
      transactionCount,
    ]
  );

  return result.rows[0];
}

// ============================================================
// HEALTH
// ============================================================

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      status: "ok",
      version: VERSION,
      network: NETWORK_NAME,
      database: "connected",
    });
  } catch (error) {
    res.status(503).json({
      status: "error",
      version: VERSION,
      network: NETWORK_NAME,
      database: "disconnected",
      message: error.message,
    });
  }
});

// ============================================================
// STATUS
// ============================================================

app.get("/api/status", async (req, res) => {
  try {
    const blockResult = await pool.query(`
      SELECT block_index
      FROM blocks
      ORDER BY block_index DESC
      LIMIT 1
    `);

    const height =
      blockResult.rows.length > 0
        ? Number(blockResult.rows[0].block_index)
        : 0;

    res.json({
      name: "SLX Network",
      version: VERSION,
      network: NETWORK_NAME,
      status: "online",
      message: "SLX Network server is running",
      networkInfo: {
        version: VERSION,
        height,
        transferFee: TRANSFER_FEE,
      },
      network_info: {
        version: VERSION,
        height,
        transferFee: TRANSFER_FEE,
      },
    });
  } catch (error) {
    console.error("STATUS ERROR:", error);

    res.status(500).json({
      error: "Failed to get status",
    });
  }
});

// ============================================================
// REGISTER
// ============================================================

app.post("/api/auth/register", async (req, res) => {
  try {
    const username = normalizeUsername(req.body.username);
    const password = String(req.body.password || "");

    if (!username) {
      return res.status(400).json({
        error: "Username is required",
      });
    }

    if (username.length < 3 || username.length > 64) {
      return res.status(400).json({
        error: "Username must contain 3-64 characters",
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error: "Password must contain at least 6 characters",
      });
    }

    const existing = await pool.query(
      `
      SELECT id
      FROM users
      WHERE LOWER(username) = LOWER($1)
      LIMIT 1
      `,
      [username]
    );

    if (existing.rows.length > 0) {
      return res.status(409).json({
        error: "Username already exists",
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const recoveryCode = generateRecoveryCode();

    const recoveryHash = await bcrypt.hash(
      recoveryCode,
      12
    );

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

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
          recoveryHash,
        ]
      );

      const user = userResult.rows[0];

      const address = generateWalletAddress();

      const walletResult = await client.query(
        `
        INSERT INTO wallets (
          user_id,
          address,
          name,
          balance
        )
        VALUES ($1, $2, $3, $4)
        RETURNING *
        `,
        [
          user.id,
          address,
          "Main Wallet",
          0,
        ]
      );

      await client.query("COMMIT");

      const token = signToken(user);

      return res.status(201).json({
        success: true,
        message: "Account created successfully",

        token,
        accessToken: token,

        recoveryCode,
        recovery_code: recoveryCode,

        user: publicUser(user),

        wallet: walletResult.rows[0],
      });
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  } catch (error) {
    console.error("REGISTER ERROR:", error);

    res.status(500).json({
      error: "Registration failed",
      message: error.message,
    });
  }
});

// ============================================================
// LOGIN
// ============================================================

app.post("/api/auth/login", async (req, res) => {
  try {
    const username = normalizeUsername(req.body.username);
    const password = String(req.body.password || "");

    const result = await pool.query(
      `
      SELECT
        id,
        username,
        password_hash,
        created_at
      FROM users
      WHERE LOWER(username) = LOWER($1)
      LIMIT 1
      `,
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        error: "Invalid username or password",
      });
    }

    const user = result.rows[0];

    const validPassword = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!validPassword) {
      return res.status(401).json({
        error: "Invalid username or password",
      });
    }

    const token = signToken(user);

    res.json({
      success: true,
      token,
      accessToken: token,
      user: publicUser(user),
    });
  } catch (error) {
    console.error("LOGIN ERROR:", error);

    res.status(500).json({
      error: "Login failed",
      message: error.message,
    });
  }
});

// ============================================================
// ME
// ============================================================

app.get(
  "/api/auth/me",
  authRequired,
  async (req, res) => {
    try {
      const wallets = await pool.query(
        `
        SELECT
          id,
          user_id,
          address,
          name,
          balance,
          created_at
        FROM wallets
        WHERE user_id = $1
        ORDER BY id ASC
        `,
        [req.user.id]
      );

      res.json({
        success: true,
        user: publicUser(req.user),
        wallets: wallets.rows,
      });
    } catch (error) {
      console.error("ME ERROR:", error);

      res.status(500).json({
        error: "Failed to load profile",
      });
    }
  }
);

// ============================================================
// RECOVERY RESET
// ============================================================

app.post(
  "/api/auth/recovery/reset",
  async (req, res) => {
    try {
      const username = normalizeUsername(
        req.body.username
      );

      const recoveryCode = String(
        req.body.recoveryCode ||
          req.body.recovery_code ||
          ""
      )
        .trim()
        .toUpperCase();

      const newPassword = String(
        req.body.newPassword || ""
      );

      if (!username || !recoveryCode) {
        return res.status(400).json({
          error: "Username and recovery code are required",
        });
      }

      if (newPassword.length < 6) {
        return res.status(400).json({
          error:
            "New password must contain at least 6 characters",
        });
      }

      const result = await pool.query(
        `
        SELECT *
        FROM users
        WHERE LOWER(username) = LOWER($1)
        LIMIT 1
        `,
        [username]
      );

      if (result.rows.length === 0) {
        return res.status(400).json({
          error: "Invalid recovery data",
        });
      }

      const user = result.rows[0];

      const validRecovery = await bcrypt.compare(
        recoveryCode,
        user.recovery_code_hash || ""
      );

      if (!validRecovery) {
        return res.status(400).json({
          error: "Invalid recovery data",
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
        [newHash, user.id]
      );

      const token = signToken(user);

      res.json({
        success: true,
        message: "Password reset successfully",
        token,
        accessToken: token,
        user: publicUser(user),
      });
    } catch (error) {
      console.error("RECOVERY ERROR:", error);

      res.status(500).json({
        error: "Recovery failed",
      });
    }
  }
);

// ============================================================
// CHANGE PASSWORD
// ============================================================

app.post(
  "/api/auth/password/change",
  authRequired,
  async (req, res) => {
    try {
      const currentPassword = String(
        req.body.currentPassword || ""
      );

      const newPassword = String(
        req.body.newPassword || ""
      );

      if (newPassword.length < 6) {
        return res.status(400).json({
          error:
            "New password must contain at least 6 characters",
        });
      }

      const result = await pool.query(
        `
        SELECT password_hash
        FROM users
        WHERE id = $1
        `,
        [req.user.id]
      );

      const valid = await bcrypt.compare(
        currentPassword,
        result.rows[0].password_hash
      );

      if (!valid) {
        return res.status(400).json({
          error: "Current password is incorrect",
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
        [newHash, req.user.id]
      );

      const token = signToken(req.user);

      res.json({
        success: true,
        message: "Password changed successfully",
        token,
        accessToken: token,
      });
    } catch (error) {
      console.error("CHANGE PASSWORD ERROR:", error);

      res.status(500).json({
        error: "Password change failed",
      });
    }
  }
);

// ============================================================
// LOGOUT
// ============================================================

app.post(
  "/api/auth/logout",
  authRequired,
  async (req, res) => {
    res.json({
      success: true,
      message: "Logged out successfully",
    });
  }
);

// ============================================================
// GET WALLETS
// ============================================================

app.get(
  "/api/wallets",
  authRequired,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT
          id,
          user_id,
          address,
          name,
          balance,
          created_at
        FROM wallets
        WHERE user_id = $1
        ORDER BY id ASC
        `,
        [req.user.id]
      );

      res.json({
        success: true,
        wallets: result.rows,
      });
    } catch (error) {
      console.error("WALLETS ERROR:", error);

      res.status(500).json({
        error: "Failed to load wallets",
      });
    }
  }
);

// ============================================================
// CREATE WALLET
// ============================================================

app.post(
  "/api/wallet/create",
  authRequired,
  async (req, res) => {
    try {
      let address;

      // Protect against an extremely unlikely duplicate.
      for (let i = 0; i < 5; i++) {
        address = generateWalletAddress();

        const exists = await pool.query(
          `
          SELECT id
          FROM wallets
          WHERE address = $1
          `,
          [address]
        );

        if (exists.rows.length === 0) {
          break;
        }
      }

      const result = await pool.query(
        `
        INSERT INTO wallets (
          user_id,
          address,
          name,
          balance
        )
        VALUES ($1, $2, $3, $4)
        RETURNING *
        `,
        [
          req.user.id,
          address,
          "SLX Wallet",
          0,
        ]
      );

      res.status(201).json({
        success: true,
        wallet: result.rows[0],
      });
    } catch (error) {
      console.error("CREATE WALLET ERROR:", error);

      res.status(500).json({
        error: "Failed to create wallet",
      });
    }
  }
);

// ============================================================
// SELECT WALLET
// ============================================================

app.post(
  "/api/wallet/select",
  authRequired,
  async (req, res) => {
    try {
      const walletId = Number(
        req.body.walletId ||
          req.body.wallet_id
      );

      if (!Number.isInteger(walletId)) {
        return res.status(400).json({
          error: "Invalid wallet ID",
        });
      }

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
          req.user.id,
        ]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          error: "Wallet not found",
        });
      }

      res.json({
        success: true,
        wallet: result.rows[0],
      });
    } catch (error) {
      console.error("SELECT WALLET ERROR:", error);

      res.status(500).json({
        error: "Failed to select wallet",
      });
    }
  }
);

// ============================================================
// WALLET DETAILS + HISTORY
// ============================================================

app.get(
  "/api/wallet/:id",
  authRequired,
  async (req, res) => {
    try {
      const walletId = Number(req.params.id);

      if (!Number.isInteger(walletId)) {
        return res.status(400).json({
          error: "Invalid wallet ID",
        });
      }

      const walletResult = await pool.query(
        `
        SELECT
          id,
          user_id,
          address,
          name,
          balance,
          created_at
        FROM wallets
        WHERE id = $1
          AND user_id = $2
        LIMIT 1
        `,
        [
          walletId,
          req.user.id,
        ]
      );

      if (walletResult.rows.length === 0) {
        return res.status(404).json({
          error: "Wallet not found",
        });
      }

      const wallet = walletResult.rows[0];

      const txResult = await pool.query(
        `
        SELECT
          t.id,
          t.tx_hash,
          t.type,
          t.from_wallet,
          t.to_wallet,
          t.amount,
          t.fee,
          t.created_at,
          t.block_id,

          fw.address AS from_address,
          tw.address AS to_address

        FROM transactions t

        LEFT JOIN wallets fw
          ON fw.id = t.from_wallet

        LEFT JOIN wallets tw
          ON tw.id = t.to_wallet

        WHERE
          t.from_wallet = $1
          OR
          t.to_wallet = $1

        ORDER BY t.created_at DESC

        LIMIT 100
        `,
        [walletId]
      );

      res.json({
        ...wallet,
        transactions: txResult.rows,
      });
    } catch (error) {
      console.error("WALLET DETAILS ERROR:", error);

      res.status(500).json({
        error: "Failed to load wallet",
      });
    }
  }
);

// ============================================================
// SEND SLX
// ============================================================

app.post(
  "/api/send",
  authRequired,
  async (req, res) => {
    const client = await pool.connect();

    try {
      const fromWalletId = Number(
        req.body.fromWalletId ||
          req.body.from_wallet_id
      );

      const toAddress = normalizeAddress(
        req.body.toAddress ||
          req.body.to_address
      );

      const amount = Number(req.body.amount);

      if (!Number.isInteger(fromWalletId)) {
        return res.status(400).json({
          error: "Invalid sender wallet",
        });
      }

      if (!isValidWalletAddress(toAddress)) {
        return res.status(400).json({
          error: "Invalid SLX address",
        });
      }

      if (!Number.isFinite(amount) || amount <= 0) {
        return res.status(400).json({
          error: "Amount must be greater than 0",
        });
      }

      const cleanAmount = roundAmount(amount);
      const fee = TRANSFER_FEE;
      const total = roundAmount(
        cleanAmount + fee
      );

      await client.query("BEGIN");

      // Lock sender wallet.
      const senderResult = await client.query(
        `
        SELECT *
        FROM wallets
        WHERE id = $1
          AND user_id = $2
        FOR UPDATE
        `,
        [
          fromWalletId,
          req.user.id,
        ]
      );

      if (senderResult.rows.length === 0) {
        await client.query("ROLLBACK");

        return res.status(404).json({
          error: "Sender wallet not found",
        });
      }

      const sender = senderResult.rows[0];

      const senderBalance = Number(
        sender.balance
      );

      if (senderBalance < total) {
        await client.query("ROLLBACK");

        return res.status(400).json({
          error: "Insufficient balance",
          balance: senderBalance,
          required: total,
        });
      }

      // Find recipient.
      const recipientResult = await client.query(
        `
        SELECT *
        FROM wallets
        WHERE address = $1
        FOR UPDATE
        `,
        [toAddress]
      );

      if (recipientResult.rows.length === 0) {
        await client.query("ROLLBACK");

        return res.status(404).json({
          error: "Recipient wallet not found",
        });
      }

      const recipient = recipientResult.rows[0];

      if (recipient.id === sender.id) {
        await client.query("ROLLBACK");

        return res.status(400).json({
          error: "Cannot send to the same wallet",
        });
      }

      // Debit sender.
      await client.query(
        `
        UPDATE wallets
        SET balance = balance - $1
        WHERE id = $2
        `,
        [
          total,
          sender.id,
        ]
      );

      // Credit recipient.
      await client.query(
        `
        UPDATE wallets
        SET balance = balance + $1
        WHERE id = $2
        `,
        [
          cleanAmount,
          recipient.id,
        ]
      );

      const txHash = generateTxHash();

      const txResult = await client.query(
        `
        INSERT INTO transactions (
          tx_hash,
          type,
          from_wallet,
          to_wallet,
          amount,
          fee
        )
        VALUES (
          $1,
          $2,
          $3,
          $4,
          $5,
          $6
        )
        RETURNING *
        `,
        [
          txHash,
          "TRANSFER",
          sender.id,
          recipient.id,
          cleanAmount,
          fee,
        ]
      );

      const block = await createBlock(
        client,
        1
      );

      await client.query(
        `
        UPDATE transactions
        SET block_id = $1
        WHERE id = $2
        `,
        [
          block.id,
          txResult.rows[0].id,
        ]
      );

      await client.query("COMMIT");

      res.json({
        success: true,
        message: "Transaction completed",
        transaction: {
          ...txResult.rows[0],
          block_id: block.id,
          block_index: block.block_index,
        },
        tx_hash: txHash,
        fee,
        amount: cleanAmount,
      });
    } catch (error) {
      await client.query("ROLLBACK");

      console.error("SEND ERROR:", error);

      res.status(500).json({
        error: "Transaction failed",
        message: error.message,
      });
    } finally {
      client.release();
    }
  }
);

// ============================================================
// FAUCET
// ============================================================

app.post(
  "/api/faucet",
  authRequired,
  async (req, res) => {
    const client = await pool.connect();

    try {
      const walletId = Number(
        req.body.walletId ||
          req.body.wallet_id
      );

      if (!Number.isInteger(walletId)) {
        return res.status(400).json({
          error: "Invalid wallet ID",
        });
      }

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
          req.user.id,
        ]
      );

      if (walletResult.rows.length === 0) {
        return res.status(404).json({
          error: "Wallet not found",
        });
      }

      // Check cooldown.
      const claimResult = await client.query(
        `
        SELECT claimed_at
        FROM faucet_claims
        WHERE user_id = $1
        ORDER BY claimed_at DESC
        LIMIT 1
        `,
        [req.user.id]
      );

      if (claimResult.rows.length > 0) {
        const lastClaim = new Date(
          claimResult.rows[0].claimed_at
        );

        const cooldownMs =
          FAUCET_COOLDOWN_HOURS *
          60 *
          60 *
          1000;

        const remaining =
          cooldownMs -
          (Date.now() - lastClaim.getTime());

        if (remaining > 0) {
          const hours = Math.ceil(
            remaining / (60 * 60 * 1000)
          );

          return res.status(429).json({
            error: "Faucet cooldown active",
            message:
              `Try again in approximately ${hours} hour(s).`,
            retryAfterSeconds: Math.ceil(
              remaining / 1000
            ),
          });
        }
      }

      await client.query("BEGIN");

      await client.query(
        `
        UPDATE wallets
        SET balance = balance + $1
        WHERE id = $2
        `,
        [
          FAUCET_AMOUNT,
          walletId,
        ]
      );

      const txHash = generateTxHash();

      const txResult = await client.query(
        `
        INSERT INTO transactions (
          tx_hash,
          type,
          from_wallet,
          to_wallet,
          amount,
          fee
        )
        VALUES (
          $1,
          $2,
          NULL,
          $3,
          $4,
          0
        )
        RETURNING *
        `,
        [
          txHash,
          "FAUCET",
          walletId,
          FAUCET_AMOUNT,
        ]
      );

      const block = await createBlock(
        client,
        1
      );

      await client.query(
        `
        UPDATE transactions
        SET block_id = $1
        WHERE id = $2
        `,
        [
          block.id,
          txResult.rows[0].id,
        ]
      );

      await client.query(
        `
        INSERT INTO faucet_claims (
          user_id,
          wallet_id
        )
        VALUES ($1, $2)
        `,
        [
          req.user.id,
          walletId,
        ]
      );

      await client.query("COMMIT");

      const updatedWallet = await pool.query(
        `
        SELECT *
        FROM wallets
        WHERE id = $1
        `,
        [walletId]
      );

      res.json({
        success: true,
        message: `Faucet sent ${FAUCET_AMOUNT} SLX`,
        amount: FAUCET_AMOUNT,
        transaction: {
          ...txResult.rows[0],
          block_id: block.id,
          block_index: block.block_index,
        },
        wallet: updatedWallet.rows[0],
      });
    } catch (error) {
      try {
        await client.query("ROLLBACK");
      } catch (_) {}

      console.error("FAUCET ERROR:", error);

      res.status(500).json({
        error: "Faucet failed",
        message: error.message,
      });
    } finally {
      client.release();
    }
  }
);

// ============================================================
// BLOCKS
// ============================================================

app.get(
  "/api/blocks",
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
        LIMIT 50
      `);

      res.json({
        success: true,
        blocks: result.rows,
      });
    } catch (error) {
      console.error("BLOCKS ERROR:", error);

      res.status(500).json({
        error: "Failed to load blocks",
      });
    }
  }
);

// ============================================================
// ECONOMY
// ============================================================

app.get(
  "/api/economy",
  authRequired,
  async (req, res) => {
    try {
      const result = await pool.query(`
        SELECT
          COALESCE(
            SUM(balance),
            0
          ) AS total_supply
        FROM wallets
      `);

      const totalSupply = Number(
        result.rows[0].total_supply || 0
      );

      res.json({
        success: true,

        totalSupply,
        total_supply: totalSupply,

        supply: totalSupply,

        maxSupply: 1000000000,
        max_supply: 1000000000,

        transferFee: TRANSFER_FEE,
        transfer_fee: TRANSFER_FEE,

        faucetAmount: FAUCET_AMOUNT,
        faucet_amount: FAUCET_AMOUNT,

        network: NETWORK_NAME,
        version: VERSION,
      });
    } catch (error) {
      console.error("ECONOMY ERROR:", error);

      res.status(500).json({
        error: "Failed to load economy",
      });
    }
  }
);

// ============================================================
// CHAIN VERIFY
// ============================================================

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

  // Genesis.
  if (blocks[0].block_index !== 0) {
    return false;
  }

  for (let i = 1; i < blocks.length; i++) {
    const current = blocks[i];
    const previous = blocks[i - 1];

    if (
      current.previous_hash !==
      previous.hash
    ) {
      return false;
    }

    if (
      Number(current.block_index) !==
      Number(previous.block_index) + 1
    ) {
      return false;
    }
  }

  return true;
}

app.post(
  "/api/chain/verify",
  authRequired,
  async (req, res) => {
    try {
      const valid = await verifyChain();

      res.json({
        success: true,
        valid,
        verified: valid,
        status: valid
          ? "valid"
          : "invalid",
        version: VERSION,
      });
    } catch (error) {
      console.error("VERIFY ERROR:", error);

      res.status(500).json({
        error: "Chain verification failed",
        valid: false,
        verified: false,
        status: "invalid",
      });
    }
  }
);

app.get(
  "/api/chain/verify",
  authRequired,
  async (req, res) => {
    try {
      const valid = await verifyChain();

      res.json({
        success: true,
        valid,
        verified: valid,
        status: valid
          ? "valid"
          : "invalid",
        version: VERSION,
      });
    } catch (error) {
      console.error("VERIFY ERROR:", error);

      res.status(500).json({
        error: "Chain verification failed",
        valid: false,
        verified: false,
        status: "invalid",
      });
    }
  }
);

// ============================================================
// 404 API
// ============================================================

app.use("/api", (req, res) => {
  res.status(404).json({
    error: "API endpoint not found",
    version: VERSION,
  });
});

// ============================================================
// FRONTEND FALLBACK
// ============================================================

app.get("*", (req, res) => {
  res.sendFile(
    path.join(__dirname, "index.html")
  );
});

// ============================================================
// ERROR HANDLER
// ============================================================

app.use(
  (err, req, res, next) => {
    console.error("SERVER ERROR:", err);

    if (res.headersSent) {
      return next(err);
    }

    res.status(500).json({
      error: "Internal server error",
      message:
        process.env.NODE_ENV === "production"
          ? "Server error"
          : err.message,
    });
  }
);

// ============================================================
// START
// ============================================================

async function startServer() {
  try {
    await initDatabase();

    app.listen(PORT, "0.0.0.0", () => {
      console.log("");
      console.log("==========================================");
      console.log("       SLX NETWORK v1.8.2");
      console.log("==========================================");
      console.log(`Network: ${NETWORK_NAME}`);
      console.log(`Port: ${PORT}`);
      console.log(`Node: ${process.version}`);
      console.log("Status: ONLINE");
      console.log("==========================================");
      console.log("");
    });
  } catch (error) {
    console.error("");
    console.error("==========================================");
    console.error("SLX NETWORK STARTUP FAILED");
    console.error("==========================================");
    console.error(error);
    console.error("==========================================");
    console.error("");

    process.exit(1);
  }
}

process.on("SIGTERM", async () => {
  console.log("SIGTERM received.");

  await pool.end();

  process.exit(0);
});

process.on("SIGINT", async () => {
  console.log("SIGINT received.");

  await pool.end();

  process.exit(0);
});

startServer();