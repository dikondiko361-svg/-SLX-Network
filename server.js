const http = require("http");
const crypto = require("crypto");
const { Pool } = require("pg");

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error("DATABASE_URL is not set");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

// ===============================
// BASIC HELPERS
// ===============================

function makeId() {
  return "SLX" + crypto.randomBytes(6).toString("hex").toUpperCase();
}

function makeUserId() {
  return "USR" + crypto.randomBytes(8).toString("hex").toUpperCase();
}

function makeAddress() {
  return "SLX-" + crypto.randomBytes(8).toString("hex").toUpperCase();
}

function makeToken() {
  return crypto.randomBytes(32).toString("hex");
}

function hashPassword(password) {
  return crypto
    .createHash("sha256")
    .update(String(password))
    .digest("hex");
}

function json(res, status, data) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS"
  });

  res.end(JSON.stringify(data));
}

function getBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";

    req.on("data", chunk => {
      body += chunk.toString();

      if (body.length > 1024 * 1024) {
        reject(new Error("Request body too large"));
        req.destroy();
      }
    });

    req.on("end", () => {
      if (!body) {
        resolve({});
        return;
      }

      try {
        resolve(JSON.parse(body));
      } catch {
        reject(new Error("Invalid JSON"));
      }
    });

    req.on("error", reject);
  });
}

function getToken(req) {
  const header = req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return null;
  }

  return header.slice(7).trim();
}

// Sessions remain in memory.
// After a server restart, users simply log in again.
const sessions = new Map();

async function getUserFromRequest(req) {
  const token = getToken(req);

  if (!token) {
    return null;
  }

  const userId = sessions.get(token);

  if (!userId) {
    return null;
  }

  const result = await pool.query(
    `SELECT id, username, created_at
     FROM users
     WHERE id = $1`,
    [userId]
  );

  return result.rows[0] || null;
}

async function requireUser(req, res) {
  const user = await getUserFromRequest(req);

  if (!user) {
    json(res, 401, {
      success: false,
      error: "Необходим вход в аккаунт"
    });

    return null;
  }

  return user;
}

function walletResponse(row) {
  return {
    id: row.id,
    name: row.name,
    address: row.address,
    balance: Number(row.balance),
    createdAt: row.created_at
  };
}

// ===============================
// DATABASE
// ===============================

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS wallets (
      id TEXT PRIMARY KEY,
      owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL DEFAULT 'Основной кошелек',
      address TEXT NOT NULL UNIQUE,
      balance NUMERIC(30, 8) NOT NULL DEFAULT 1000,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS transactions (
      id TEXT PRIMARY KEY,
      wallet_id TEXT NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
      type TEXT NOT NULL,
      amount NUMERIC(30, 8) NOT NULL,
      from_wallet TEXT,
      to_wallet TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_wallets_owner
    ON wallets(owner_id)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_transactions_wallet
    ON transactions(wallet_id, created_at DESC)
  `);

  console.log("PostgreSQL database ready");
}

// ===============================
// SERVER
// ===============================

const server = http.createServer(async (req, res) => {
  if (req.method === "OPTIONS") {
    json(res, 204, {});
    return;
  }

  try {
    const url = new URL(
      req.url,
      `http://${req.headers.host || "localhost"}`
    );

    const pathname = url.pathname;

    // =============================
    // HOME
    // =============================

    if (req.method === "GET" && pathname === "/") {
      const fs = require("fs");
      const path = require("path");

      const file = path.join(__dirname, "index.html");

      if (!fs.existsSync(file)) {
        json(res, 404, {
          success: false,
          error: "index.html not found"
        });
        return;
      }

      res.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8"
      });

      res.end(fs.readFileSync(file));
      return;
    }

    // =============================
    // STATUS
    // =============================

    if (req.method === "GET" && pathname === "/api/status") {
      const users = await pool.query(
        `SELECT COUNT(*)::int AS count FROM users`
      );

      const wallets = await pool.query(
        `SELECT COUNT(*)::int AS count FROM wallets`
      );

      json(res, 200, {
        success: true,
        network: "SLX Testnet",
        version: "1.4.0",
        status: "online",
        storage: "PostgreSQL",
        accounts: users.rows[0].count,
        wallets: wallets.rows[0].count
      });

      return;
    }

    // =============================
    // REGISTER
    // =============================

    if (req.method === "POST" && pathname === "/api/auth/register") {
      const body = await getBody(req);

      const username = String(body.username || "").trim();
      const password = String(body.password || "");

      if (username.length < 3) {
        json(res, 400, {
          success: false,
          error: "Имя пользователя должно содержать минимум 3 символа"
        });
        return;
      }

      if (password.length < 4) {
        json(res, 400, {
          success: false,
          error: "Пароль должен содержать минимум 4 символа"
        });
        return;
      }

      const existing = await pool.query(
        `SELECT id FROM users WHERE LOWER(username) = LOWER($1)`,
        [username]
      );

      if (existing.rows.length > 0) {
        json(res, 409, {
          success: false,
          error: "Такой пользователь уже существует"
        });
        return;
      }

      const client = await pool.connect();

      try {
        await client.query("BEGIN");

        const userId = makeUserId();
        const walletId = makeId();
        const address = makeAddress();
        const passwordHash = hashPassword(password);

        await client.query(
          `INSERT INTO users
           (id, username, password_hash)
           VALUES ($1, $2, $3)`,
          [userId, username, passwordHash]
        );

        await client.query(
          `INSERT INTO wallets
           (id, owner_id, name, address, balance)
           VALUES ($1, $2, $3, $4, $5)`,
          [
            walletId,
            userId,
            "Основной кошелек",
            address,
            1000
          ]
        );

        const token = makeToken();

        await client.query("COMMIT");

        sessions.set(token, userId);

        json(res, 201, {
          success: true,
          token,
          user: {
            id: userId,
            username,
            walletId,
            walletIds: [walletId]
          }
        });

        return;
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        client.release();
      }
    }

    // =============================
    // LOGIN
    // =============================

    if (req.method === "POST" && pathname === "/api/auth/login") {
      const body = await getBody(req);

      const username = String(body.username || "").trim();
      const password = String(body.password || "");

      const result = await pool.query(
        `SELECT id, username, password_hash
         FROM users
         WHERE LOWER(username) = LOWER($1)`,
        [username]
      );

      if (result.rows.length === 0) {
        json(res, 401, {
          success: false,
          error: "Неверное имя пользователя или пароль"
        });
        return;
      }

      const user = result.rows[0];
      const passwordHash = hashPassword(password);

      if (passwordHash !== user.password_hash) {
        json(res, 401, {
          success: false,
          error: "Неверное имя пользователя или пароль"
        });
        return;
      }

      const walletsResult = await pool.query(
        `SELECT id
         FROM wallets
         WHERE owner_id = $1
         ORDER BY created_at ASC`,
        [user.id]
      );

      const walletIds = walletsResult.rows.map(row => row.id);
      const walletId = walletIds[0] || null;

      const token = makeToken();

      sessions.set(token, user.id);

      json(res, 200, {
        success: true,
        token,
        user: {
          id: user.id,
          username: user.username,
          walletId,
          walletIds
        }
      });

      return;
    }

    // =============================
    // CURRENT USER
    // =============================

    if (req.method === "GET" && pathname === "/api/auth/me") {
      const user = await requireUser(req, res);

      if (!user) return;

      const walletsResult = await pool.query(
        `SELECT id
         FROM wallets
         WHERE owner_id = $1
         ORDER BY created_at ASC`,
        [user.id]
      );

      const walletIds = walletsResult.rows.map(row => row.id);

      json(res, 200, {
        success: true,
        user: {
          id: user.id,
          username: user.username,
          walletId: walletIds[0] || null,
          walletIds
        }
      });

      return;
    }

    // =============================
    // LOGOUT
    // =============================

    if (req.method === "POST" && pathname === "/api/auth/logout") {
      const token = getToken(req);

      if (token) {
        sessions.delete(token);
      }

      json(res, 200, {
        success: true
      });

      return;
    }

    // =============================
    // CREATE WALLET
    // =============================

    if (req.method === "POST" && pathname === "/api/wallet/create") {
      const user = await requireUser(req, res);

      if (!user) return;

      const body = await getBody(req);

      const name =
        String(body.name || "").trim() ||
        "Кошелек " + Date.now();

      const walletId = makeId();
      const address = makeAddress();

      const result = await pool.query(
        `INSERT INTO wallets
         (id, owner_id, name, address, balance)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, name, address, balance, created_at`,
        [
          walletId,
          user.id,
          name,
          address,
          1000
        ]
      );

      json(res, 201, {
        success: true,
        wallet: walletResponse(result.rows[0])
      });

      return;
    }

    // =============================
    // LIST MY WALLETS
    // =============================

    if (req.method === "GET" && pathname === "/api/wallets") {
      const user = await requireUser(req, res);

      if (!user) return;

      const result = await pool.query(
        `SELECT id, name, address, balance, created_at
         FROM wallets
         WHERE owner_id = $1
         ORDER BY created_at ASC`,
        [user.id]
      );

      json(res, 200, {
        success: true,
        wallets: result.rows.map(walletResponse)
      });

      return;
    }

    // =============================
    // SELECT WALLET
    // =============================

    if (req.method === "POST" && pathname === "/api/wallet/select") {
      const user = await requireUser(req, res);

      if (!user) return;

      const body = await getBody(req);
      const walletId = String(body.walletId || "");

      const result = await pool.query(
        `SELECT id, name, address, balance, created_at
         FROM wallets
         WHERE id = $1 AND owner_id = $2`,
        [walletId, user.id]
      );

      if (result.rows.length === 0) {
        json(res, 404, {
          success: false,
          error: "Кошелек не найден"
        });
        return;
      }

      json(res, 200, {
        success: true,
        wallet: walletResponse(result.rows[0])
      });

      return;
    }

    // =============================
    // GET WALLET
    // =============================

    if (req.method === "GET" && pathname.startsWith("/api/wallet/")) {
      const user = await requireUser(req, res);

      if (!user) return;

      const walletId = pathname.split("/").pop();

      const walletResult = await pool.query(
        `SELECT id, name, address, balance, created_at
         FROM wallets
         WHERE id = $1 AND owner_id = $2`,
        [walletId, user.id]
      );

      if (walletResult.rows.length === 0) {
        json(res, 404, {
          success: false,
          error: "Кошелек не найден"
        });
        return;
      }

      const transactionsResult = await pool.query(
        `SELECT
           id,
           type,
           amount,
           from_wallet,
           to_wallet,
           created_at
         FROM transactions
         WHERE wallet_id = $1
         ORDER BY created_at DESC
         LIMIT 100`,
        [walletId]
      );

      json(res, 200, {
        success: true,
        wallet: walletResponse(walletResult.rows[0]),
        transactions: transactionsResult.rows.map(tx => ({
          id: tx.id,
          type: tx.type,
          amount: Number(tx.amount),
          from: tx.from_wallet,
          to: tx.to_wallet,
          time: tx.created_at
        }))
      });

      return;
    }

    // =============================
    // FIND WALLET
    // =============================

    if (req.method === "GET" && pathname.startsWith("/api/find/")) {
      const id = pathname.split("/").pop();

      const result = await pool.query(
        `SELECT id, name, address, balance, created_at
         FROM wallets
         WHERE id = $1 OR address = $1`,
        [id]
      );

      if (result.rows.length === 0) {
        json(res, 404, {
          success: false,
          error: "Кошелек не найден"
        });
        return;
      }

      json(res, 200, {
        success: true,
        wallet: walletResponse(result.rows[0])
      });

      return;
    }

    // =============================
    // FAUCET
    // =============================

    if (req.method === "POST" && pathname === "/api/faucet") {
      const user = await requireUser(req, res);

      if (!user) return;

      const body = await getBody(req);
      const walletId = String(body.walletId || "");

      const client = await pool.connect();

      try {
        await client.query("BEGIN");

        const walletResult = await client.query(
          `SELECT id, balance
           FROM wallets
           WHERE id = $1 AND owner_id = $2
           FOR UPDATE`,
          [walletId, user.id]
        );

        if (walletResult.rows.length === 0) {
          await client.query("ROLLBACK");

          json(res, 404, {
            success: false,
            error: "Кошелек не найден"
          });

          return;
        }

        const amount = 100;
        const txId = makeId();

        await client.query(
          `UPDATE wallets
           SET balance = balance + $1
           WHERE id = $2`,
          [amount, walletId]
        );

        await client.query(
          `INSERT INTO transactions
           (id, wallet_id, type, amount, from_wallet, to_wallet)
           VALUES ($1, $2, $3, $4, $5, $6)`,
          [
            txId,
            walletId,
            "faucet",
            amount,
            "SLX-FAUCET",
            walletId
          ]
        );

        const updated = await client.query(
          `SELECT id, name, address, balance, created_at
           FROM wallets
           WHERE id = $1`,
          [walletId]
        );

        await client.query("COMMIT");

        json(res, 200, {
          success: true,
          amount,
          wallet: walletResponse(updated.rows[0])
        });

        return;
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        client.release();
      }
    }

    // =============================
    // SEND SLX
    // =============================

    if (req.method === "POST" && pathname === "/api/send") {
      const user = await requireUser(req, res);

      if (!user) return;

      const body = await getBody(req);

      const senderId = String(body.senderId || "");
      const recipientId = String(body.recipientId || "");
      const amount = Number(body.amount);

      if (!senderId || !recipientId) {
        json(res, 400, {
          success: false,
          error: "Не указан отправитель или получатель"
        });
        return;
      }

      if (senderId === recipientId) {
        json(res, 400, {
          success: false,
          error: "Нельзя отправить самому себе"
        });
        return;
      }

      if (!Number.isFinite(amount) || amount <= 0) {
        json(res, 400, {
          success: false,
          error: "Неверная сумма"
        });
        return;
      }

      const client = await pool.connect();

      try {
        await client.query("BEGIN");

        // Sender must belong to current user.
        const senderResult = await client.query(
          `SELECT id, balance
           FROM wallets
           WHERE id = $1 AND owner_id = $2
           FOR UPDATE`,
          [senderId, user.id]
        );

        if (senderResult.rows.length === 0) {
          await client.query("ROLLBACK");

          json(res, 403, {
            success: false,
            error: "Этот кошелек вам не принадлежит"
          });

          return;
        }

        // Lock recipient wallet.
        const recipientResult = await client.query(
          `SELECT id, balance
           FROM wallets
           WHERE id = $1
           FOR UPDATE`,
          [recipientId]
        );

        if (recipientResult.rows.length === 0) {
          await client.query("ROLLBACK");

          json(res, 404, {
            success: false,
            error: "Кошелек получателя не найден"
          });

          return;
        }

        const senderBalance = Number(senderResult.rows[0].balance);

        if (senderBalance < amount) {
          await client.query("ROLLBACK");

          json(res, 400, {
            success: false,
            error: "Недостаточно SLX"
          });

          return;
        }

        const txId = makeId();

        await client.query(
          `UPDATE wallets
           SET balance = balance - $1
           WHERE id = $2`,
          [amount, senderId]
        );

        await client.query(
          `UPDATE wallets
           SET balance = balance + $1
           WHERE id = $2`,
          [amount, recipientId]
        );

        await client.query(
          `INSERT INTO transactions
           (id, wallet_id, type, amount, from_wallet, to_wallet)
           VALUES
           ($1, $2, 'send', $3, $4, $5),
           ($1 || '-R', $5, 'receive', $3, $4, $5)`,
          [
            txId,
            senderId,
            amount,
            senderId,
            recipientId
          ]
        );

        const updatedSender = await client.query(
          `SELECT id, name, address, balance, created_at
           FROM wallets
           WHERE id = $1`,
          [senderId]
        );

        await client.query("COMMIT");

        json(res, 200, {
          success: true,
          transaction: {
            id: txId,
            amount,
            from: senderId,
            to: recipientId
          },
          wallet: walletResponse(updatedSender.rows[0])
        });

        return;
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        client.release();
      }
    }

    // =============================
    // 404
    // =============================

    json(res, 404, {
      success: false,
      error: "Not found"
    });

  } catch (error) {
    console.error("SERVER ERROR:", error);

    json(res, 500, {
      success: false,
      error: "Внутренняя ошибка сервера"
    });
  }
});

// ===============================
// START
// ===============================

async function start() {
  try {
    await initDatabase();

    server.listen(PORT, () => {
      console.log("================================");
      console.log("SLX Network v1.4.0");
      console.log("Storage: PostgreSQL");
      console.log(`Port: ${PORT}`);
      console.log("================================");
    });
  } catch (error) {
    console.error("DATABASE STARTUP ERROR:", error);
    process.exit(1);
  }
}

start();