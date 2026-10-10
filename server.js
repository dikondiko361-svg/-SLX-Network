"use strict";

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { Pool } = require("pg");
const path = require("path");

const app = express();

const PORT = Number(process.env.PORT || 10000);
const VERSION = "1.8.2";
const NETWORK_NAME = "SLX-Testnet";
const TRANSFER_FEE = 0.1;
const FAUCET_AMOUNT = 10;
const MAX_SUPPLY = 1000000000;

const JWT_SECRET =
  process.env.JWT_SECRET ||
  "SLX_TESTNET_DEV_SECRET_CHANGE_ME_1_8_2";

if (!process.env.JWT_SECRET) {
  console.warn(
    "WARNING: JWT_SECRET is not set. Set JWT_SECRET in Render Environment."
  );
}

/* =========================================================
   DATABASE
========================================================= */

if (!process.env.DATABASE_URL) {
  console.error("ERROR: DATABASE_URL is missing.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.NODE_ENV === "production"
      ? { rejectUnauthorized: false }
      : false,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

pool.on("error", (err) => {
  console.error("PostgreSQL pool error:", err);
});

/* =========================================================
   EXPRESS
========================================================= */

app.use(
  cors({
    origin: true,
    credentials: true
  })
);

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

/* =========================================================
   HELPERS
========================================================= */

function nowISO() {
  return new Date().toISOString();
}

function randomHex(bytes = 16) {
  return crypto.randomBytes(bytes).toString("hex").toUpperCase();
}

function makeWalletAddress() {
  // Exactly:
  // SLXC + 32 hexadecimal characters
  return "SLXC" + randomHex(16);
}

function makeRecoveryCode() {
  return randomHex(6);
}

function makeTxHash() {
  return "0x" + crypto.randomBytes(32).toString("hex");
}

function makeBlockHash() {
  return "0x" + crypto.randomBytes(32).toString("hex");
}

function makeJWT(user) {
  return jwt.sign(
    {
      id: user.id,
      username: user.username
    },
    JWT_SECRET,
    {
      expiresIn: "30d"
    }
  );
}

function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    created_at: user.created_at
  };
}

function normalizeAmount(value) {
  const n = Number(value);

  if (!Number.isFinite(n)) {
    return null;
  }

  return Math.round(n * 1000000) / 1000000;
}

function validWalletAddress(address) {
  return /^SLXC[A-F0-9]{32}$/.test(String(address || ""));
}

function sendError(res, status, message, extra = {}) {
  return res.status(status).json({
    ok: false,
    error: message,
    message,
    ...extra
  });
}

/* =========================================================
   AUTH MIDDLEWARE
========================================================= */

function authRequired(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return sendError(res, 401, "Authentication required");
    }

    const token = header.slice(7).trim();

    if (!token) {
      return sendError(res, 401, "Authentication required");
    }

    const decoded = jwt.verify(token, JWT_SECRET);

    req.user = decoded;

    next();
  } catch (err) {
    return sendError(res, 401, "Invalid or expired token");
  }
}

/* =========================================================
   DATABASE INIT
========================================================= */

async function initDatabase() {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(64) NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        recovery_code_hash TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS wallets (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        address VARCHAR(36) NOT NULL UNIQUE,
        balance NUMERIC(30, 6) NOT NULL DEFAULT 0,
        name VARCHAR(100),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS transactions (
        id SERIAL PRIMARY KEY,
        tx_hash VARCHAR(100) NOT NULL UNIQUE,
        type VARCHAR(30) NOT NULL,
        from_wallet VARCHAR(36),
        to_wallet VARCHAR(36),
        amount NUMERIC(30, 6) NOT NULL DEFAULT 0,
        fee NUMERIC(30, 6) NOT NULL DEFAULT 0,
        block_id INTEGER,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS blocks (
        id SERIAL PRIMARY KEY,
        block_index INTEGER NOT NULL UNIQUE,
        timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        hash VARCHAR(100) NOT NULL UNIQUE,
        previous_hash VARCHAR(100),
        transaction_count INTEGER NOT NULL DEFAULT 0
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS faucet_claims (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        wallet_id INTEGER NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
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
      CREATE INDEX IF NOT EXISTS idx_faucet_claims_user
      ON faucet_claims(user_id)
    `);

    const genesis = await client.query(
      `SELECT id FROM blocks WHERE block_index = 0 LIMIT 1`
    );

    if (genesis.rowCount === 0) {
      await client.query(
        `
        INSERT INTO blocks
          (block_index, timestamp, hash, previous_hash, transaction_count)
        VALUES
          ($1, NOW(), $2, NULL, 0)
        `,
        [0, "0x" + "0".repeat(64)]
      );
    }

    await client.query("COMMIT");

    console.log("Database initialized.");
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Database initialization failed:", err);
    throw err;
  } finally {
    client.release();
  }
}

/* =========================================================
   BLOCKCHAIN HELPERS
========================================================= */

async function createBlock(client, transactionCount = 1) {
  const result = await client.query(`
    SELECT
      block_index,
      hash
    FROM blocks
    ORDER BY block_index DESC
    LIMIT 1
  `);

  const lastBlock = result.rows[0];

  const nextIndex = lastBlock
    ? Number(lastBlock.block_index) + 1
    : 0;

  const previousHash = lastBlock
    ? lastBlock.hash
    : "0x" + "0".repeat(64);

  const hash = makeBlockHash();

  const inserted = await client.query(
    `
    INSERT INTO blocks
      (
        block_index,
        timestamp,
        hash,
        previous_hash,
        transaction_count
      )
    VALUES
      ($1, NOW(), $2, $3, $4)
    RETURNING *
    `,
    [
      nextIndex,
      hash,
      previousHash,
      transactionCount
    ]
  );

  return inserted.rows[0];
}

/* =========================================================
   HEALTH
========================================================= */

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      ok: true,
      status: "online",
      version: VERSION,
      network: NETWORK_NAME,
      timestamp: nowISO()
    });
  } catch (err) {
    res.status(503).json({
      ok: false,
      status: "offline",
      error: "Database unavailable"
    });
  }
});

/* =========================================================
   ROOT
========================================================= */

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

/* =========================================================
   STATUS
========================================================= */

app.get("/api/status", async (req, res) => {
  try {
    const heightResult = await pool.query(`
      SELECT COALESCE(MAX(block_index), 0) AS height
      FROM blocks
    `);

    const height = Number(heightResult.rows[0].height || 0);

    res.json({
      name: "SLX Network",
      version: VERSION,
      network: NETWORK_NAME,
      status: "online",
      message: "SLX Network server is running",
      height,
      blockHeight: height,
      networkInfo: {
        name: NETWORK_NAME,
        version: VERSION,
        height,
        transferFee: TRANSFER_FEE
      }
    });
  } catch (err) {
    console.error("/api/status:", err);

    res.status(500).json({
      name: "SLX Network",
      version: VERSION,
      network: NETWORK_NAME,
      status: "error",
      message: "Database error"
    });
  }
});

/* =========================================================
   REGISTER
========================================================= */

app.post("/api/auth/register", async (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");

  if (!username || !password) {
    return sendError(
      res,
      400,
      "Username and password are required"
    );
  }

  if (!/^[A-Za-z0-9_]{3,32}$/.test(username)) {
    return sendError(
      res,
      400,
      "Username must contain 3-32 letters, numbers or underscore"
    );
  }

  if (password.length < 6) {
    return sendError(
      res,
      400,
      "Password must be at least 6 characters"
    );
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

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
      await client.query("ROLLBACK");

      return sendError(
        res,
        409,
        "Username already exists"
      );
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const recoveryCode = makeRecoveryCode();

    const recoveryCodeHash = await bcrypt.hash(
      recoveryCode,
      10
    );

    const userResult = await client.query(
      `
      INSERT INTO users
        (username, password_hash, recovery_code_hash)
      VALUES
        ($1, $2, $3)
      RETURNING *
      `,
      [
        username,
        passwordHash,
        recoveryCodeHash
      ]
    );

    const user = userResult.rows[0];

    const walletAddress = makeWalletAddress();

    const walletResult = await client.query(
      `
      INSERT INTO wallets
        (user_id, address, balance, name)
      VALUES
        ($1, $2, $3, $4)
      RETURNING *
      `,
      [
        user.id,
        walletAddress,
        0,
        "Main Wallet"
      ]
    );

    await client.query("COMMIT");

    const token = makeJWT(user);

    return res.status(201).json({
      ok: true,
      token,
      accessToken: token,
      recoveryCode,
      recovery_code: recoveryCode,
      user: publicUser(user),
      wallet: walletResult.rows[0]
    });
  } catch (err) {
    await client.query("ROLLBACK");

    console.error("Registration error:", err);

    return sendError(
      res,
      500,
      "Registration failed"
    );
  } finally {
    client.release();
  }
});

/* =========================================================
   LOGIN
========================================================= */

app.post("/api/auth/login", async (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");

  if (!username || !password) {
    return sendError(
      res,
      400,
      "Username and password are required"
    );
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
      return sendError(
        res,
        401,
        "Invalid username or password"
      );
    }

    const user = result.rows[0];

    const valid = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!valid) {
      return sendError(
        res,
        401,
        "Invalid username or password"
      );
    }

    const token = makeJWT(user);

    return res.json({
      ok: true,
      token,
      accessToken: token,
      user: publicUser(user)
    });
  } catch (err) {
    console.error("Login error:", err);

    return sendError(
      res,
      500,
      "Login failed"
    );
  }
});

/* =========================================================
   ME
========================================================= */

app.get("/api/auth/me", authRequired, async (req, res) => {
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
      return sendError(
        res,
        404,
        "User not found"
      );
    }

    res.json({
      ok: true,
      user: publicUser(result.rows[0])
    });
  } catch (err) {
    console.error("/api/auth/me:", err);

    return sendError(
      res,
      500,
      "Failed to load user"
    );
  }
});

/* =========================================================
   RECOVERY RESET
========================================================= */

app.post("/api/auth/recovery/reset", async (req, res) => {
  const username = String(req.body.username || "").trim();
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

  if (!username || !recoveryCode || !newPassword) {
    return sendError(
      res,
      400,
      "Invalid recovery data"
    );
  }

  if (newPassword.length < 6) {
    return sendError(
      res,
      400,
      "New password must be at least 6 characters"
    );
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
      return sendError(
        res,
        400,
        "Invalid recovery data"
      );
    }

    const user = result.rows[0];

    const valid = await bcrypt.compare(
      recoveryCode,
      user.recovery_code_hash
    );

    if (!valid) {
      return sendError(
        res,
        400,
        "Invalid recovery data"
      );
    }

    const passwordHash = await bcrypt.hash(
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
        passwordHash,
        user.id
      ]
    );

    const token = makeJWT(user);

    return res.json({
      ok: true,
      message: "Password reset successfully",
      token,
      accessToken: token,
      user: publicUser(user)
    });
  } catch (err) {
    console.error("Recovery error:", err);

    return sendError(
      res,
      500,
      "Recovery failed"
    );
  }
});

/* =========================================================
   CHANGE PASSWORD
========================================================= */

app.post(
  "/api/auth/password/change",
  authRequired,
  async (req, res) => {
    const currentPassword = String(
      req.body.currentPassword || ""
    );

    const newPassword = String(
      req.body.newPassword || ""
    );

    if (!currentPassword || !newPassword) {
      return sendError(
        res,
        400,
        "Current and new password are required"
      );
    }

    if (newPassword.length < 6) {
      return sendError(
        res,
        400,
        "New password must be at least 6 characters"
      );
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
        return sendError(
          res,
          404,
          "User not found"
        );
      }

      const user = result.rows[0];

      const valid = await bcrypt.compare(
        currentPassword,
        user.password_hash
      );

      if (!valid) {
        return sendError(
          res,
          400,
          "Current password is incorrect"
        );
      }

      const passwordHash = await bcrypt.hash(
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
          passwordHash,
          user.id
        ]
      );

      const token = makeJWT(user);

      return res.json({
        ok: true,
        message: "Password changed",
        token,
        accessToken: token
      });
    } catch (err) {
      console.error("Password change error:", err);

      return sendError(
        res,
        500,
        "Password change failed"
      );
    }
  }
);

/* =========================================================
   LOGOUT
========================================================= */

app.post(
  "/api/auth/logout",
  authRequired,
  async (req, res) => {
    res.json({
      ok: true,
      message: "Logged out"
    });
  }
);

/* =========================================================
   GET WALLETS
========================================================= */

app.get("/api/wallets", authRequired, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT
        id,
        user_id,
        address,
        balance,
        name,
        created_at
      FROM wallets
      WHERE user_id = $1
      ORDER BY id ASC
      `,
      [req.user.id]
    );

    res.json({
      ok: true,
      wallets: result.rows
    });
  } catch (err) {
    console.error("/api/wallets:", err);

    return sendError(
      res,
      500,
      "Failed to load wallets"
    );
  }
});

/* =========================================================
   CREATE WALLET
========================================================= */

app.post(
  "/api/wallet/create",
  authRequired,
  async (req, res) => {
    try {
      let address;

      for (let i = 0; i < 10; i++) {
        const candidate = makeWalletAddress();

        const exists = await pool.query(
          `
          SELECT id
          FROM wallets
          WHERE address = $1
          LIMIT 1
          `,
          [candidate]
        );

        if (exists.rowCount === 0) {
          address = candidate;
          break;
        }
      }

      if (!address) {
        return sendError(
          res,
          500,
          "Could not generate wallet address"
        );
      }

      const countResult = await pool.query(
        `
        SELECT COUNT(*)::int AS count
        FROM wallets
        WHERE user_id = $1
        `,
        [req.user.id]
      );

      const count = Number(
        countResult.rows[0].count || 0
      );

      const name =
        count === 0
          ? "Main Wallet"
          : `Wallet ${count + 1}`;

      const result = await pool.query(
        `
        INSERT INTO wallets
          (user_id, address, balance, name)
        VALUES
          ($1, $2, 0, $3)
        RETURNING *
        `,
        [
          req.user.id,
          address,
          name
        ]
      );

      res.status(201).json({
        ok: true,
        wallet: result.rows[0]
      });
    } catch (err) {
      console.error("Create wallet error:", err);

      return sendError(
        res,
        500,
        "Failed to create wallet"
      );
    }
  }
);

/* =========================================================
   SELECT WALLET
========================================================= */

app.post(
  "/api/wallet/select",
  authRequired,
  async (req, res) => {
    const walletId = Number(req.body.walletId);

    if (!Number.isInteger(walletId)) {
      return sendError(
        res,
        400,
        "Invalid wallet ID"
      );
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
        return sendError(
          res,
          404,
          "Wallet not found"
        );
      }

      res.json({
        ok: true,
        wallet: result.rows[0]
      });
    } catch (err) {
      console.error("Select wallet error:", err);

      return sendError(
        res,
        500,
        "Failed to select wallet"
      );
    }
  }
);

/* =========================================================
   WALLET DETAILS + TRANSACTIONS
========================================================= */

app.get(
  "/api/wallet/:id",
  authRequired,
  async (req, res) => {
    const walletId = Number(req.params.id);

    if (!Number.isInteger(walletId)) {
      return sendError(
        res,
        400,
        "Invalid wallet ID"
      );
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
        return sendError(
          res,
          404,
          "Wallet not found"
        );
      }

      const wallet = walletResult.rows[0];

      const txResult = await pool.query(
        `
        SELECT
          id,
          tx_hash,
          type,
          from_wallet,
          to_wallet,
          amount,
          fee,
          block_id,
          created_at
        FROM transactions
        WHERE from_wallet = $1
           OR to_wallet = $1
        ORDER BY created_at DESC
        LIMIT 100
        `,
        [wallet.address]
      );

      res.json({
        ok: true,
        wallet,
        transactions: txResult.rows
      });
    } catch (err) {
      console.error("Wallet details error:", err);

      return sendError(
        res,
        500,
        "Failed to load wallet"
      );
    }
  }
);

/* =========================================================
   SEND
========================================================= */

app.post(
  "/api/send",
  authRequired,
  async (req, res) => {
    const fromWalletId = Number(
      req.body.fromWalletId
    );

    const toAddress = String(
      req.body.toAddress || ""
    )
      .trim()
      .toUpperCase();

    const amount = normalizeAmount(
      req.body.amount
    );

    if (!Number.isInteger(fromWalletId)) {
      return sendError(
        res,
        400,
        "Invalid sender wallet"
      );
    }

    if (!validWalletAddress(toAddress)) {
      return sendError(
        res,
        400,
        "Invalid SLX wallet address"
      );
    }

    if (
      amount === null ||
      amount <= 0
    ) {
      return sendError(
        res,
        400,
        "Invalid amount"
      );
    }

    if (
      amount >
      1000000000000000
    ) {
      return sendError(
        res,
        400,
        "Amount is too large"
      );
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

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
          req.user.id
        ]
      );

      if (senderResult.rowCount === 0) {
        await client.query("ROLLBACK");

        return sendError(
          res,
          404,
          "Sender wallet not found"
        );
      }

      const sender = senderResult.rows[0];

      if (sender.address === toAddress) {
        await client.query("ROLLBACK");

        return sendError(
          res,
          400,
          "Cannot send to the same wallet"
        );
      }

      const totalRequired =
        amount + TRANSFER_FEE;

      const senderBalance =
        Number(sender.balance);

      if (
        !Number.isFinite(senderBalance) ||
        senderBalance < totalRequired
      ) {
        await client.query("ROLLBACK");

        return sendError(
          res,
          400,
          "Insufficient balance",
          {
            balance: senderBalance,
            required: totalRequired
          }
        );
      }

      const receiverResult = await client.query(
        `
        SELECT *
        FROM wallets
        WHERE address = $1
        FOR UPDATE
        `,
        [toAddress]
      );

      if (receiverResult.rowCount === 0) {
        await client.query("ROLLBACK");

        return sendError(
          res,
          404,
          "Recipient wallet not found"
        );
      }

      const receiver =
        receiverResult.rows[0];

      const txHash = makeTxHash();

      const newSenderBalance =
        senderBalance - totalRequired;

      const newReceiverBalance =
        Number(receiver.balance) + amount;

      await client.query(
        `
        UPDATE wallets
        SET balance = $1
        WHERE id = $2
        `,
        [
          newSenderBalance,
          sender.id
        ]
      );

      await client.query(
        `
        UPDATE wallets
        SET balance = $1
        WHERE id = $2
        `,
        [
          newReceiverBalance,
          receiver.id
        ]
      );

      const txResult = await client.query(
        `
        INSERT INTO transactions
          (
            tx_hash,
            type,
            from_wallet,
            to_wallet,
            amount,
            fee
          )
        VALUES
          (
            $1,
            'TRANSFER',
            $2,
            $3,
            $4,
            $5
          )
        RETURNING *
        `,
        [
          txHash,
          sender.address,
          receiver.address,
          amount,
          TRANSFER_FEE
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
          txResult.rows[0].id
        ]
      );

      await client.query("COMMIT");

      return res.json({
        ok: true,
        message: "Transaction successful",
        transaction: {
          ...txResult.rows[0],
          block_id: block.id
        },
        txHash,
        block
      });
    } catch (err) {
      await client.query("ROLLBACK");

      console.error("Send error:", err);

      return sendError(
        res,
        500,
        "Transaction failed"
      );
    } finally {
      client.release();
    }
  }
);

/* =========================================================
   FAUCET
========================================================= */

app.post(
  "/api/faucet",
  authRequired,
  async (req, res) => {
    const walletId = Number(
      req.body.walletId
    );

    if (!Number.isInteger(walletId)) {
      return sendError(
        res,
        400,
        "Invalid wallet ID"
      );
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

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
        await client.query("ROLLBACK");

        return sendError(
          res,
          404,
          "Wallet not found"
        );
      }

      const wallet =
        walletResult.rows[0];

      const lastClaimResult =
        await client.query(
          `
          SELECT claimed_at
          FROM faucet_claims
          WHERE user_id = $1
          ORDER BY claimed_at DESC
          LIMIT 1
          `,
          [req.user.id]
        );

      if (lastClaimResult.rowCount > 0) {
        const lastClaim = new Date(
          lastClaimResult.rows[0].claimed_at
        );

        const elapsed =
          Date.now() - lastClaim.getTime();

        const cooldown =
          24 * 60 * 60 * 1000;

        if (elapsed < cooldown) {
          const remaining =
            cooldown - elapsed;

          const hours = Math.ceil(
            remaining / 3600000
          );

          await client.query("ROLLBACK");

          return sendError(
            res,
            429,
            `Faucet cooldown active. Try again in ${hours}h`,
            {
              cooldownHours: hours
            }
          );
        }
      }

      const newBalance =
        Number(wallet.balance) +
        FAUCET_AMOUNT;

      await client.query(
        `
        UPDATE wallets
        SET balance = $1
        WHERE id = $2
        `,
        [
          newBalance,
          wallet.id
        ]
      );

      await client.query(
        `
        INSERT INTO faucet_claims
          (user_id, wallet_id)
        VALUES
          ($1, $2)
        `,
        [
          req.user.id,
          wallet.id
        ]
      );

      const txHash = makeTxHash();

      const txResult = await client.query(
        `
        INSERT INTO transactions
          (
            tx_hash,
            type,
            from_wallet,
            to_wallet,
            amount,
            fee
          )
        VALUES
          (
            $1,
            'FAUCET',
            NULL,
            $2,
            $3,
            0
          )
        RETURNING *
        `,
        [
          txHash,
          wallet.address,
          FAUCET_AMOUNT
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
          txResult.rows[0].id
        ]
      );

      await client.query("COMMIT");

      return res.json({
        ok: true,
        message: `Received ${FAUCET_AMOUNT} SLX`,
        amount: FAUCET_AMOUNT,
        wallet: {
          ...wallet,
          balance: newBalance
        },
        transaction: {
          ...txResult.rows[0],
          block_id: block.id
        },
        block
      });
    } catch (err) {
      await client.query("ROLLBACK");

      console.error("Faucet error:", err);

      return sendError(
        res,
        500,
        "Faucet failed"
      );
    } finally {
      client.release();
    }
  }
);

/* =========================================================
   BLOCKS
========================================================= */

app.get("/api/blocks", async (req, res) => {
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
      ok: true,
      blocks: result.rows
    });
  } catch (err) {
    console.error("/api/blocks:", err);

    return sendError(
      res,
      500,
      "Failed to load blocks"
    );
  }
});

/* =========================================================
   ECONOMY
========================================================= */

app.get("/api/economy", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        COALESCE(
          SUM(balance),
          0
        ) AS total_balance
      FROM wallets
    `);

    const totalBalance = Number(
      result.rows[0].total_balance || 0
    );

    res.json({
      ok: true,

      totalSupply: totalBalance,
      total_supply: totalBalance,
      supply: totalBalance,

      maxSupply: MAX_SUPPLY,
      max_supply: MAX_SUPPLY,

      transferFee: TRANSFER_FEE,
      transfer_fee: TRANSFER_FEE,

      faucetAmount: FAUCET_AMOUNT
    });
  } catch (err) {
    console.error("/api/economy:", err);

    return sendError(
      res,
      500,
      "Failed to load economy"
    );
  }
});

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
    return {
      valid: false,
      verified: false,
      status: "invalid",
      reason: "No blocks"
    };
  }

  if (
    Number(blocks[0].block_index) !== 0
  ) {
    return {
      valid: false,
      verified: false,
      status: "invalid",
      reason: "Genesis block missing"
    };
  }

  for (let i = 1; i < blocks.length; i++) {
    const previous = blocks[i - 1];
    const current = blocks[i];

    if (
      Number(current.block_index) !==
      Number(previous.block_index) + 1
    ) {
      return {
        valid: false,
        verified: false,
        status: "invalid",
        reason: "Invalid block sequence"
      };
    }

    if (
      current.previous_hash !==
      previous.hash
    ) {
      return {
        valid: false,
        verified: false,
        status: "invalid",
        reason: "Broken previous hash"
      };
    }
  }

  return {
    valid: true,
    verified: true,
    status: "valid",
    blockCount: blocks.length
  };
}

app.post(
  "/api/chain/verify",
  async (req, res) => {
    try {
      const result = await verifyChain();

      res.json(result);
    } catch (err) {
      console.error("Chain verify error:", err);

      return sendError(
        res,
        500,
        "Chain verification failed"
      );
    }
  }
);

app.get(
  "/api/chain/verify",
  async (req, res) => {
    try {
      const result = await verifyChain();

      res.json(result);
    } catch (err) {
      console.error("Chain verify error:", err);

      return sendError(
        res,
        500,
        "Chain verification failed"
      );
    }
  }
);

/* =========================================================
   404
========================================================= */

app.use("/api", (req, res) => {
  return sendError(
    res,
    404,
    "API endpoint not found"
  );
});

/* =========================================================
   GLOBAL ERROR HANDLER
========================================================= */

app.use((err, req, res, next) => {
  console.error("Unhandled server error:", err);

  if (res.headersSent) {
    return next(err);
  }

  return sendError(
    res,
    500,
    "Internal server error"
  );
});

/* =========================================================
   START
========================================================= */

async function startServer() {
  try {
    await initDatabase();

    app.listen(PORT, "0.0.0.0", () => {
      console.log("======================================");
      console.log("SLX Network v1.8.2");
      console.log("Network:", NETWORK_NAME);
      console.log("Port:", PORT);
      console.log("Status: ONLINE");
      console.log("======================================");
    });
  } catch (err) {
    console.error("SERVER START FAILED");
    console.error(err);
    process.exit(1);
  }
}

startServer();