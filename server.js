const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { Pool } = require("pg");

const PORT = process.env.PORT || 10000;
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error("DATABASE_URL is missing");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

// ============================================================
// SLX NETWORK v1.8.2
// Core Update
// Testnet
// ============================================================

const NETWORK_VERSION = "1.8.2";

const MAX_SUPPLY = 21000000;
const TRANSFER_FEE = 0.1;
const FAUCET_AMOUNT = 10;
const INITIAL_BALANCE = 1000;

// Faucet cooldown: 24 hours
const FAUCET_COOLDOWN_MS = 24 * 60 * 60 * 1000;

// Maximum request body
const MAX_BODY_SIZE = 1024 * 1024;

const sessions = new Map();

// ============================================================
// Helpers
// ============================================================

function walletCardHTML(wallet){
  const activeId = localStorage.getItem("slx_active_wallet");
  const isActive = String(wallet.id) === String(activeId);

  const balance = Number(wallet.balance ?? wallet.amount ?? 0);

  const address = wallet.address || "";

  const shortAddress =
    address.length > 18
      ? address.slice(0, 10) + "..." + address.slice(-6)
      : address;

  const walletId = String(wallet.id || "unknown");

  const shortWalletId =
    walletId.length > 17
      ? walletId.slice(0, 12) + "..."
      : walletId;

  return `
    <div class="wallet-card ${isActive ? "active" : ""}">

      <div class="wallet-icon">S</div>

      <div class="wallet-main">

        <div class="wallet-title">
          Wallet #${escapeHtml(shortWalletId)}
        </div>

        <div class="wallet-address">
          ${escapeHtml(shortAddress)}
        </div>

        ${
          isActive
            ? `
              <div class="wallet-status">
                <span class="wallet-status-dot"></span>
                Активный
              </div>
            `
            : ""
        }

      </div>

      <div class="wallet-right">

        <div class="wallet-balance">
          ${formatSLX(balance)} SLX
        </div>

        ${
          isActive
            ? ""
            : `
              <button
                class="wallet-select"
                onclick="selectWallet('${escapeJs(wallet.id)}')"
              >
                Выбрать
              </button>
            `
        }

      </div>

    </div>
  `;
}
function isValidUsername(username) {
  return /^[a-zA-Z0-9_.-]{3,32}$/.test(username);
}

function isValidAddress(address) {
  return /^SLXC[A-F0-9]{32}$/.test(address);
}

function isValidAmount(value) {
  return (
    Number.isFinite(value) &&
    value > 0 &&
    value <= MAX_SUPPLY &&
    Number.isInteger(value * 100000000)
  );
}

// ============================================================
// Password Security
// ============================================================

async function hashPassword(password) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16).toString("hex");

    crypto.scrypt(
      password,
      salt,
      64,
      {
        N: 16384,
        r: 8,
        p: 1
      },
      (err, derivedKey) => {
        if (err) return reject(err);

        resolve(
          "scrypt$" +
          salt +
          "$" +
          derivedKey.toString("hex")
        );
      }
    );
  });
}

async function verifyPassword(password, stored) {
  if (!stored) return false;

  if (stored.startsWith("scrypt$")) {
    const parts = stored.split("$");

    if (parts.length !== 3) {
      return false;
    }

    const salt = parts[1];
    const originalHash = parts[2];

    return new Promise((resolve, reject) => {
      crypto.scrypt(
        password,
        salt,
        64,
        {
          N: 16384,
          r: 8,
          p: 1
        },
        (err, derivedKey) => {
          if (err) return reject(err);

          const newHash = derivedKey.toString("hex");

          try {
            const a = Buffer.from(originalHash, "hex");
            const b = Buffer.from(newHash, "hex");

            if (a.length !== b.length) {
              return resolve(false);
            }

            resolve(
              crypto.timingSafeEqual(a, b)
            );
          } catch {
            resolve(false);
          }
        }
      );
    });
  }

  // Legacy v1.5 SHA-256
  return sha256(password) === stored;
}

// ============================================================
// Sessions
// ============================================================

function createSession(userId) {
  const token = crypto.randomBytes(32).toString("hex");

  sessions.set(token, {
    userId,
    createdAt: Date.now()
  });

  return token;
}

function getToken(req) {
  const auth = req.headers.authorization || "";

  if (!auth.startsWith("Bearer ")) {
    return null;
  }

  return auth.slice(7).trim();
}

function getUserId(req) {
  const token = getToken(req);

  if (!token) {
    return null;
  }

  const session = sessions.get(token);

  if (!session) {
    return null;
  }

  return session.userId;
}

function requireAuth(req, res) {
  const userId = getUserId(req);

  if (!userId) {
    json(res, 401, {
      success: false,
      error: "Требуется вход"
    });

    return null;
  }

  return userId;
}

// ============================================================
// Body
// ============================================================

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    let size = 0;

    req.on("data", chunk => {
      size += chunk.length;

      if (size > MAX_BODY_SIZE) {
        reject(new Error("Request too large"));
        req.destroy();
        return;
      }

      body += chunk.toString();
    });

    req.on("end", () => {
      if (!body) {
        return resolve({});
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

// ============================================================
// Blockchain
// ============================================================

function calculateTransactionHash(tx) {
  return sha256(
    JSON.stringify({
      id: tx.id,
      type: tx.type,
      amount: tx.amount,
      from_wallet: tx.from_wallet,
      to_wallet: tx.to_wallet
    })
  );
}

function calculateMerkleRoot(transactions) {
  if (!transactions.length) {
    return sha256("EMPTY");
  }

  let hashes = transactions.map(
    calculateTransactionHash
  );

  while (hashes.length > 1) {
    const next = [];

    for (let i = 0; i < hashes.length; i += 2) {
      const left = hashes[i];
      const right = hashes[i + 1] || left;

      next.push(
        sha256(left + right)
      );
    }

    hashes = next;
  }

  return hashes[0];
}

function calculateBlockHash(block) {
  return sha256(
    [
      block.index,
      block.previous_hash,
      block.timestamp,
      block.miner,
      block.transaction_count,
      block.merkle_root
    ].join("|")
  );
}

async function getLastBlock(client = pool) {
  const result = await client.query(`
    SELECT *
    FROM blocks
    ORDER BY block_index DESC
    LIMIT 1
  `);

  return result.rows[0] || null;
}

async function createBlock(
  client,
  miner,
  transactionRows
) {
  const previous = await getLastBlock(client);

  const index = previous
    ? Number(previous.block_index) + 1
    : 0;

  const previousHash = previous
    ? previous.hash
    : "GENESIS";

  const timestamp =
    new Date().toISOString();

  const merkleRoot =
    calculateMerkleRoot(transactionRows);

  const blockData = {
    index,
    previous_hash: previousHash,
    timestamp,
    miner,
    transaction_count:
      transactionRows.length,
    merkle_root: merkleRoot
  };

  const hash =
    calculateBlockHash(blockData);

  const blockId =
    makeId("BLK_");

  await client.query(
    `
    INSERT INTO blocks
      (
        id,
        block_index,
        previous_hash,
        hash,
        timestamp,
        miner,
        transaction_count,
        merkle_root
      )
    VALUES
      ($1,$2,$3,$4,$5,$6,$7,$8)
    `,
    [
      blockId,
      index,
      previousHash,
      hash,
      timestamp,
      miner,
      transactionRows.length,
      merkleRoot
    ]
  );

  return {
    id: blockId,
    index,
    hash,
    previous_hash: previousHash,
    timestamp,
    transaction_count:
      transactionRows.length,
    merkle_root: merkleRoot
  };
}

// ============================================================
// Database
// ============================================================

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      recovery_code_hash TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS recovery_code_hash TEXT
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS wallets (
      id TEXT PRIMARY KEY,
      owner_id TEXT NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,
      address TEXT UNIQUE NOT NULL,
      balance NUMERIC(30,8) NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS transactions (
      id TEXT PRIMARY KEY,
      wallet_id TEXT NOT NULL
        REFERENCES wallets(id)
        ON DELETE CASCADE,
      type TEXT NOT NULL,
      amount NUMERIC(30,8) NOT NULL,
      fee NUMERIC(30,8) DEFAULT 0,
      from_wallet TEXT,
      to_wallet TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    ALTER TABLE transactions
    ADD COLUMN IF NOT EXISTS fee NUMERIC(30,8) DEFAULT 0
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS blocks (
      id TEXT PRIMARY KEY,
      block_index BIGINT UNIQUE NOT NULL,
      previous_hash TEXT NOT NULL,
      hash TEXT UNIQUE NOT NULL,
      timestamp TIMESTAMPTZ NOT NULL,
      miner TEXT NOT NULL,
      transaction_count INTEGER NOT NULL DEFAULT 0,
      merkle_root TEXT NOT NULL
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS network_state (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS faucet_claims (
      wallet_id TEXT PRIMARY KEY
        REFERENCES wallets(id)
        ON DELETE CASCADE,
      last_claim_at TIMESTAMPTZ NOT NULL
    )
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_wallet_owner
    ON wallets(owner_id)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_tx_wallet
    ON transactions(wallet_id)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_blocks_index
    ON blocks(block_index)
  `);

  await pool.query(`
    INSERT INTO network_state(key, value)
    VALUES
      ('max_supply', $1),
      ('transfer_fee', $2),
      ('faucet_amount', $3),
      ('network_version', $4)
    ON CONFLICT (key)
    DO UPDATE SET value = EXCLUDED.value
  `, [
    String(MAX_SUPPLY),
    String(TRANSFER_FEE),
    String(FAUCET_AMOUNT),
    NETWORK_VERSION
  ]);

  // ==========================================================
  // Genesis
  // ==========================================================

  const blockCount =
    await pool.query(`
      SELECT COUNT(*)::int AS count
      FROM blocks
    `);

  if (blockCount.rows[0].count === 0) {
    const timestamp =
      new Date().toISOString();

    const genesis = {
      index: 0,
      previous_hash: "GENESIS",
      timestamp,
      miner: "SLX_NETWORK",
      transaction_count: 0,
      merkle_root:
        sha256("SLX_GENESIS")
    };

    const genesisHash =
      calculateBlockHash(genesis);

    await pool.query(`
      INSERT INTO blocks
        (
          id,
          block_index,
          previous_hash,
          hash,
          timestamp,
          miner,
          transaction_count,
          merkle_root
        )
      VALUES
        ($1,$2,$3,$4,$5,$6,$7,$8)
    `, [
      "GENESIS",
      0,
      "GENESIS",
      genesisHash,
      timestamp,
      "SLX_NETWORK",
      0,
      genesis.merkle_root
    ]);

    console.log(
      "SLX genesis block created:",
      genesisHash
    );
  }

  console.log(
    `SLX Network v${NETWORK_VERSION} database ready`
  );
}

// ============================================================
// HTTP SERVER
// ============================================================

const server =
  http.createServer(async (req, res) => {
    try {
      const url = new URL(
        req.url,
        `http://${req.headers.host || "localhost"}`
      );

      const pathname = url.pathname;

      // ======================================================
      // FRONTEND
      // ======================================================

      if (
        req.method === "GET" &&
        pathname === "/"
      ) {
        const file =
          path.join(__dirname, "index.html");

        if (!fs.existsSync(file)) {
          return sendText(
            res,
            404,
            "index.html not found"
          );
        }

        return sendText(
          res,
          200,
          fs.readFileSync(file, "utf8"),
          "text/html; charset=utf-8"
        );
      }

      // ======================================================
      // STATUS
      // ======================================================

      if (
        req.method === "GET" &&
        pathname === "/api/status"
      ) {
        const users =
          await pool.query(`
            SELECT COUNT(*)::int AS count
            FROM users
          `);

        const wallets =
          await pool.query(`
            SELECT COUNT(*)::int AS count
            FROM wallets
          `);

        const transactions =
          await pool.query(`
            SELECT COUNT(*)::int AS count
            FROM transactions
          `);

        const blocks =
          await pool.query(`
            SELECT COUNT(*)::int AS count
            FROM blocks
          `);

        const supply =
          await pool.query(`
            SELECT COALESCE(
              SUM(balance),0
            ) AS total
            FROM wallets
          `);

        return json(res, 200, {
          success: true,
          version: NETWORK_VERSION,
          network: "SLX Testnet",
          status: "online",
          users: users.rows[0].count,
          wallets: wallets.rows[0].count,
          transactions:
            transactions.rows[0].count,
          blocks: blocks.rows[0].count,
          maxSupply: MAX_SUPPLY,
          circulatingSupply:
            Number(supply.rows[0].total),
          transferFee: TRANSFER_FEE,
          faucetAmount: FAUCET_AMOUNT
        });
      }

      // ======================================================
      // REGISTER
      // ======================================================

      if (
        req.method === "POST" &&
        pathname === "/api/auth/register"
      ) {
        const body =
          await readBody(req);

        const username =
          String(body.username || "").trim();

        const password =
          String(body.password || "");

        if (!isValidUsername(username)) {
          return json(res, 400, {
            success: false,
            error:
              "Имя: 3-32 символа, только латиница, цифры, _, -, ."
          });
        }

        if (password.length < 6) {
          return json(res, 400, {
            success: false,
            error:
              "Пароль должен содержать минимум 6 символов"
          });
        }

        const existing =
          await pool.query(
            `
            SELECT id
            FROM users
            WHERE username=$1
            `,
            [username]
          );

        if (existing.rows.length) {
          return json(res, 409, {
            success: false,
            error:
              "Пользователь уже существует"
          });
        }

        // Check supply BEFORE giving initial balance
        const supplyResult =
          await pool.query(`
            SELECT COALESCE(
              SUM(balance),0
            ) AS total
            FROM wallets
          `);

        const currentSupply =
          Number(
            supplyResult.rows[0].total
          );

        if (
          currentSupply +
            INITIAL_BALANCE >
          MAX_SUPPLY
        ) {
          return json(res, 400, {
            success: false,
            error:
              "Невозможно создать стартовый баланс: достигнут максимальный выпуск SLX"
          });
        }

        const client =
          await pool.connect();

        try {
          await client.query("BEGIN");

          // Prevent concurrent supply overshoot
          await client.query(`
            SELECT pg_advisory_xact_lock(827364)
          `);

          const lockedSupply =
            await client.query(`
              SELECT COALESCE(
                SUM(balance),0
              ) AS total
              FROM wallets
            `);

          const total =
            Number(
              lockedSupply.rows[0].total
            );

          if (
            total + INITIAL_BALANCE >
            MAX_SUPPLY
          ) {
            await client.query("ROLLBACK");

            return json(res, 400, {
              success: false,
              error:
                "Достигнут максимальный выпуск SLX"
            });
          }

          const userId =
            makeId("USR_");

          const walletId =
            makeId("WLT_");

          const address =
            makeAddress();

          const passwordHash =
            await hashPassword(password);

          // Recovery code
          const recoveryCode =
            crypto.randomBytes(6)
              .toString("hex")
              .toUpperCase();

          const recoveryHash =
            sha256(recoveryCode);

          await client.query(`
            INSERT INTO users
              (
                id,
                username,
                password_hash,
                recovery_code_hash
              )
            VALUES
              ($1,$2,$3,$4)
          `, [
            userId,
            username,
            passwordHash,
            recoveryHash
          ]);

          await client.query(`
            INSERT INTO wallets
              (
                id,
                owner_id,
                address,
                balance
              )
            VALUES
              ($1,$2,$3,$4)
          `, [
            walletId,
            userId,
            address,
            INITIAL_BALANCE
          ]);

          const txId =
            makeId("TX_");

          await client.query(`
            INSERT INTO transactions
              (
                id,
                wallet_id,
                type,
                amount,
                fee,
                from_wallet,
                to_wallet
              )
            VALUES
              (
                $1,$2,'GENESIS',$3,0,
                'NETWORK',$4
              )
          `, [
            txId,
            walletId,
            INITIAL_BALANCE,
            address
          ]);

          const txRows = [{
            id: txId,
            type: "GENESIS",
            amount: INITIAL_BALANCE,
            from_wallet: "NETWORK",
            to_wallet: address
          }];

          const block =
            await createBlock(
              client,
              "NETWORK",
              txRows
            );

          await client.query("COMMIT");

          const token =
            createSession(userId);

          return json(res, 200, {
            success: true,
            token,

            user: {
              id: userId,
              username
            },

            wallet: {
              id: walletId,
              address,
              balance: INITIAL_BALANCE
            },

            recoveryCode,

            block
          });
        } catch (error) {
          await client.query("ROLLBACK");
          throw error;
        } finally {
          client.release();
        }
      }

      // ======================================================
      // LOGIN
      // ======================================================

      if (
        req.method === "POST" &&
        pathname === "/api/auth/login"
      ) {
        const body =
          await readBody(req);

        const username =
          String(body.username || "")
            .trim();

        const password =
          String(body.password || "");

        const result =
          await pool.query(`
            SELECT *
            FROM users
            WHERE username=$1
          `, [username]);

        if (!result.rows.length) {
          return json(res, 401, {
            success: false,
            error:
              "Неверный логин или пароль"
          });
        }

        const user =
          result.rows[0];

        const valid =
          await verifyPassword(
            password,
            user.password_hash
          );

        if (!valid) {
          return json(res, 401, {
            success: false,
            error:
              "Неверный логин или пароль"
          });
        }

        // Upgrade old SHA-256 password
        if (
          !user.password_hash
            .startsWith("scrypt$")
        ) {
          const newHash =
            await hashPassword(password);

          await pool.query(`
            UPDATE users
            SET password_hash=$1
            WHERE id=$2
          `, [
            newHash,
            user.id
          ]);
        }

        const token =
          createSession(user.id);

        return json(res, 200, {
          success: true,
          token,
          user: {
            id: user.id,
            username: user.username
          }
        });
      }

      // ======================================================
      // ME
      // ======================================================

      if (
        req.method === "GET" &&
        pathname === "/api/auth/me"
      ) {
        const userId =
          requireAuth(req, res);

        if (!userId) return;

        const result =
          await pool.query(`
            SELECT
              id,
              username,
              created_at
            FROM users
            WHERE id=$1
          `, [userId]);

        if (!result.rows.length) {
          return json(res, 404, {
            success: false,
            error:
              "Пользователь не найден"
          });
        }

        return json(res, 200, {
          success: true,
          user: result.rows[0]
        });
      }

      // ======================================================
      // CHANGE PASSWORD
      // ======================================================

      if (
        req.method === "POST" &&
        pathname === "/api/auth/password/change"
      ) {
        const userId =
          requireAuth(req, res);

        if (!userId) return;

        const body =
          await readBody(req);

        const oldPassword =
          String(
            body.oldPassword || ""
          );

        const newPassword =
          String(
            body.newPassword || ""
          );

        if (newPassword.length < 6) {
          return json(res, 400, {
            success: false,
            error:
              "Новый пароль должен содержать минимум 6 символов"
          });
        }

        const result =
          await pool.query(`
            SELECT password_hash
            FROM users
            WHERE id=$1
          `, [userId]);

        if (!result.rows.length) {
          return json(res, 404, {
            success: false,
            error:
              "Пользователь не найден"
          });
        }

        const valid =
          await verifyPassword(
            oldPassword,
            result.rows[0].password_hash
          );

        if (!valid) {
          return json(res, 401, {
            success: false,
            error:
              "Старый пароль неверен"
          });
        }

        const newHash =
          await hashPassword(
            newPassword
          );

        await pool.query(`
          UPDATE users
          SET password_hash=$1
          WHERE id=$2
        `, [
          newHash,
          userId
        ]);

        // Invalidate all sessions
        for (
          const [token, session]
          of sessions.entries()
        ) {
          if (
            session.userId === userId
          ) {
            sessions.delete(token);
          }
        }

        const token =
          createSession(userId);

        return json(res, 200, {
          success: true,
          token
        });
      }

      // ======================================================
      // RECOVERY RESET
      // ======================================================

      if (
        req.method === "POST" &&
        pathname === "/api/auth/recovery/reset"
      ) {
        const body =
          await readBody(req);

        const username =
          String(
            body.username || ""
          ).trim();

        const recoveryCode =
          String(
            body.recoveryCode || ""
          ).trim().toUpperCase();

        const newPassword =
          String(
            body.newPassword || ""
          );

        if (
          newPassword.length < 6
        ) {
          return json(res, 400, {
            success: false,
            error:
              "Новый пароль должен содержать минимум 6 символов"
          });
        }

        const result =
          await pool.query(`
            SELECT
              id,
              recovery_code_hash
            FROM users
            WHERE username=$1
          `, [username]);

        if (!result.rows.length) {
          return json(res, 400, {
            success: false,
            error:
              "Неверные данные восстановления"
          });
        }

        const user =
          result.rows[0];

        if (
          !user.recovery_code_hash ||
          sha256(recoveryCode) !==
            user.recovery_code_hash
        ) {
          return json(res, 401, {
            success: false,
            error:
              "Неверные данные восстановления"
          });
        }

        const newHash =
          await hashPassword(
            newPassword
          );

        await pool.query(`
          UPDATE users
          SET password_hash=$1
          WHERE id=$2
        `, [
          newHash,
          user.id
        ]);

        for (
          const [token, session]
          of sessions.entries()
        ) {
          if (
            session.userId === user.id
          ) {
            sessions.delete(token);
          }
        }

        const token =
          createSession(user.id);

        return json(res, 200, {
          success: true,
          token
        });
      }

      // ======================================================
      // LOGOUT
      // ======================================================

      if (
        req.method === "POST" &&
        pathname === "/api/auth/logout"
      ) {
        const token =
          getToken(req);

        if (token) {
          sessions.delete(token);
        }

        return json(res, 200, {
          success: true
        });
      }

      // ======================================================
      // WALLETS
      // ======================================================

      if (
        req.method === "GET" &&
        pathname === "/api/wallets"
      ) {
        const userId =
          requireAuth(req, res);

        if (!userId) return;

        const result =
          await pool.query(`
            SELECT
              id,
              address,
              balance,
              created_at
            FROM wallets
            WHERE owner_id=$1
            ORDER BY created_at ASC
          `, [userId]);

        return json(res, 200, {
          success: true,
          wallets: result.rows
        });
      }

      // ======================================================
      // CREATE WALLET
      // ======================================================

      if (
        req.method === "POST" &&
        pathname === "/api/wallet/create"
      ) {
        const userId =
          requireAuth(req, res);

        if (!userId) return;

        const walletId =
          makeId("WLT_");

        const address =
          makeAddress();

        await pool.query(`
          INSERT INTO wallets
            (
              id,
              owner_id,
              address,
              balance
            )
          VALUES
            ($1,$2,$3,0)
        `, [
          walletId,
          userId,
          address
        ]);

        return json(res, 200, {
          success: true,
          wallet: {
            id: walletId,
            address,
            balance: 0
          }
        });
      }

      // ======================================================
      // SELECT WALLET
      // ======================================================

      if (
        req.method === "POST" &&
        pathname === "/api/wallet/select"
      ) {
        const userId =
          requireAuth(req, res);

        if (!userId) return;

        const body =
          await readBody(req);

        const walletId =
          String(
            body.walletId || ""
          );

        const result =
          await pool.query(`
            SELECT
              id,
              address,
              balance
            FROM wallets
            WHERE id=$1
              AND owner_id=$2
          `, [
            walletId,
            userId
          ]);

        if (!result.rows.length) {
          return json(res, 404, {
            success: false,
            error:
              "Кошелёк не найден"
          });
        }

        return json(res, 200, {
          success: true,
          wallet: result.rows[0]
        });
      }

      // ======================================================
      // WALLET INFO
      // ======================================================

      if (
        req.method === "GET" &&
        pathname.startsWith(
          "/api/wallet/"
        )
      ) {
        const userId =
          requireAuth(req, res);

        if (!userId) return;

        const walletId =
          pathname.split("/").pop();

        const wallet =
          await pool.query(`
            SELECT
              id,
              address,
              balance,
              created_at
            FROM wallets
            WHERE id=$1
              AND owner_id=$2
          `, [
            walletId,
            userId
          ]);

        if (!wallet.rows.length) {
          return json(res, 404, {
            success: false,
            error:
              "Кошелёк не найден"
          });
        }

        const transactions =
          await pool.query(`
            SELECT *
            FROM transactions
            WHERE wallet_id=$1
            ORDER BY created_at DESC
            LIMIT 100
          `, [walletId]);

        return json(res, 200, {
          success: true,
          wallet: wallet.rows[0],
          transactions:
            transactions.rows
        });
      }

      // ======================================================
      // FIND WALLET
      // ======================================================

      if (
        req.method === "GET" &&
        pathname.startsWith(
          "/api/find/"
        )
      ) {
        const value =
          decodeURIComponent(
            pathname.split("/").pop()
          );

        const result =
          await pool.query(`
            SELECT
              id,
              address,
              balance
            FROM wallets
            WHERE id=$1
               OR address=$1
          `, [value]);

        if (!result.rows.length) {
          return json(res, 404, {
            success: false,
            error:
              "Кошелёк не найден"
          });
        }

        return json(res, 200, {
          success: true,
          wallet: result.rows[0]
        });
      }

      // ======================================================
      // FAUCET
      // ======================================================

      if (
        req.method === "POST" &&
        pathname === "/api/faucet"
      ) {
        const userId =
          requireAuth(req, res);

        if (!userId) return;

        const body =
          await readBody(req);

        const walletId =
          String(
            body.walletId || ""
          );

        const client =
          await pool.connect();

        try {
          await client.query(
            "BEGIN"
          );

          // Global supply lock
          await client.query(`
            SELECT pg_advisory_xact_lock(827364)
          `);

          const walletResult =
            await client.query(`
              SELECT *
              FROM wallets
              WHERE id=$1
                AND owner_id=$2
              FOR UPDATE
            `, [
              walletId,
              userId
            ]);

          if (!walletResult.rows.length) {
            await client.query(
              "ROLLBACK"
            );

            return json(res, 404, {
              success: false,
              error:
                "Кошелёк не найден"
            });
          }

          const wallet =
            walletResult.rows[0];

          // Cooldown
          const claimResult =
            await client.query(`
              SELECT last_claim_at
              FROM faucet_claims
              WHERE wallet_id=$1
              FOR UPDATE
            `, [walletId]);

          if (claimResult.rows.length) {
            const lastClaim =
              new Date(
                claimResult.rows[0]
                  .last_claim_at
              ).getTime();

            const elapsed =
              Date.now() - lastClaim;

            if (
              elapsed <
              FAUCET_COOLDOWN_MS
            ) {
              const remaining =
                FAUCET_COOLDOWN_MS -
                elapsed;

              const minutes =
                Math.ceil(
                  remaining / 60000
                );

              await client.query(
                "ROLLBACK"
              );

              return json(res, 429, {
                success: false,
                error:
                  `Faucet доступен снова примерно через ${minutes} минут`
              });
            }
          }

          const supplyResult =
            await client.query(`
              SELECT COALESCE(
                SUM(balance),0
              ) AS total
              FROM wallets
            `);

          const totalSupply =
            Number(
              supplyResult.rows[0]
                .total
            );

          if (
            totalSupply +
              FAUCET_AMOUNT >
            MAX_SUPPLY
          ) {
            await client.query(
              "ROLLBACK"
            );

            return json(res, 400, {
              success: false,
              error:
                "Достигнут максимальный выпуск SLX"
            });
          }

          const txId =
            makeId("TX_");

          await client.query(`
            UPDATE wallets
            SET balance =
              balance + $1
            WHERE id=$2
          `, [
            FAUCET_AMOUNT,
            walletId
          ]);

          await client.query(`
            INSERT INTO transactions
              (
                id,
                wallet_id,
                type,
                amount,
                fee,
                from_wallet,
                to_wallet
              )
            VALUES
              (
                $1,$2,'FAUCET',
                $3,0,'FAUCET',$4
              )
          `, [
            txId,
            walletId,
            FAUCET_AMOUNT,
            wallet.address
          ]);

          await client.query(`
            INSERT INTO faucet_claims
              (
                wallet_id,
                last_claim_at
              )
            VALUES
              ($1,NOW())
            ON CONFLICT(wallet_id)
            DO UPDATE SET
              last_claim_at =
                EXCLUDED.last_claim_at
          `, [walletId]);

          const txRows = [{
            id: txId,
            type: "FAUCET",
            amount: FAUCET_AMOUNT,
            from_wallet: "FAUCET",
            to_wallet:
              wallet.address
          }];

          const block =
            await createBlock(
              client,
              "FAUCET",
              txRows
            );

          await client.query(
            "COMMIT"
          );

          return json(res, 200, {
            success: true,
            amount: FAUCET_AMOUNT,
            nextClaimIn:
              FAUCET_COOLDOWN_MS,
            block
          });
        } catch (error) {
          await client.query(
            "ROLLBACK"
          );

          throw error;
        } finally {
          client.release();
        }
      }

      // ======================================================
      // SEND
      // ======================================================

      if (
        req.method === "POST" &&
        pathname === "/api/send"
      ) {
        const userId =
          requireAuth(req, res);

        if (!userId) return;

        const body =
          await readBody(req);

        const fromWalletId =
          String(
            body.fromWalletId || ""
          );

        const toAddress =
          String(
            body.to || ""
          ).trim().toUpperCase();

        const amount =
          Number(body.amount);

        if (
          !fromWalletId ||
          !toAddress
        ) {
          return json(res, 400, {
            success: false,
            error:
              "Не указан кошелёк или получатель"
          });
        }

        if (
          !isValidAddress(toAddress)
        ) {
          return json(res, 400, {
            success: false,
            error:
              "Некорректный адрес SLX"
          });
        }

        if (
          !isValidAmount(amount)
        ) {
          return json(res, 400, {
            success: false,
            error:
              "Некорректная сумма"
          });
        }

        const client =
          await pool.connect();

        try {
          await client.query(
            "BEGIN"
          );

          // Lock sender first
          const senderResult =
            await client.query(`
              SELECT *
              FROM wallets
              WHERE id=$1
                AND owner_id=$2
              FOR UPDATE
            `, [
              fromWalletId,
              userId
            ]);

          if (
            !senderResult.rows.length
          ) {
            await client.query(
              "ROLLBACK"
            );

            return json(res, 403, {
              success: false,
              error:
                "Этот кошелёк вам не принадлежит"
            });
          }

          const sender =
            senderResult.rows[0];

          const recipientResult =
            await client.query(`
              SELECT *
              FROM wallets
              WHERE address=$1
              FOR UPDATE
            `, [toAddress]);

          if (
            !recipientResult.rows.length
          ) {
            await client.query(
              "ROLLBACK"
            );

            return json(res, 404, {
              success: false,
              error:
                "Кошелёк получателя не найден"
            });
          }

          const recipient =
            recipientResult.rows[0];

          if (
            recipient.id ===
            sender.id
          ) {
            await client.query(
              "ROLLBACK"
            );

            return json(res, 400, {
              success: false,
              error:
                "Нельзя отправить самому себе"
            });
          }

          const totalCost =
            amount +
            TRANSFER_FEE;

          if (
            Number(sender.balance) <
            totalCost
          ) {
            await client.query(
              "ROLLBACK"
            );

            return json(res, 400, {
              success: false,
              error:
                `Недостаточно средств. Нужно ${totalCost} SLX`
            });
          }

          const txId =
            makeId("TX_");

          // Sender
          await client.query(`
            UPDATE wallets
            SET balance =
              balance - $1
            WHERE id=$2
          `, [
            totalCost,
            sender.id
          ]);

          // Recipient
          await client.query(`
            UPDATE wallets
            SET balance =
              balance + $1
            WHERE id=$2
          `, [
            amount,
            recipient.id
          ]);

          // Sender transaction
          await client.query(`
            INSERT INTO transactions
              (
                id,
                wallet_id,
                type,
                amount,
                fee,
                from_wallet,
                to_wallet
              )
            VALUES
              (
                $1,$2,'SEND',
                $3,$4,$5,$6
              )
          `, [
            txId,
            sender.id,
            amount,
            TRANSFER_FEE,
            sender.address,
            recipient.address
          ]);

          // Recipient transaction
          await client.query(`
            INSERT INTO transactions
              (
                id,
                wallet_id,
                type,
                amount,
                fee,
                from_wallet,
                to_wallet
              )
            VALUES
              (
                $1,$2,'RECEIVE',
                $3,0,$4,$5
              )
          `, [
            txId + "-R",
            recipient.id,
            amount,
            sender.address,
            recipient.address
          ]);

          const txRows = [
            {
              id: txId,
              type: "SEND",
              amount,
              from_wallet:
                sender.address,
              to_wallet:
                recipient.address
            },
            {
              id: txId + "-R",
              type: "RECEIVE",
              amount,
              from_wallet:
                sender.address,
              to_wallet:
                recipient.address
            }
          ];

          const block =
            await createBlock(
              client,
              sender.address,
              txRows
            );

          await client.query(
            "COMMIT"
          );

          return json(res, 200, {
            success: true,

            transaction: {
              id: txId,
              amount,
              fee: TRANSFER_FEE,
              total: totalCost,
              from:
                sender.address,
              to:
                recipient.address
            },

            block
          });
        } catch (error) {
          await client.query(
            "ROLLBACK"
          );

          throw error;
        } finally {
          client.release();
        }
      }

      // ======================================================
      // BLOCKS
      // ======================================================

      if (
        req.method === "GET" &&
        pathname === "/api/blocks"
      ) {
        const result =
          await pool.query(`
            SELECT *
            FROM blocks
            ORDER BY block_index DESC
            LIMIT 50
          `);

        return json(res, 200, {
          success: true,
          blocks: result.rows
        });
      }

      // ======================================================
      // SINGLE BLOCK
      // ======================================================

      if (
        req.method === "GET" &&
        pathname.startsWith(
          "/api/block/"
        )
      ) {
        const value =
          decodeURIComponent(
            pathname.split("/").pop()
          );

        const result =
          await pool.query(`
            SELECT *
            FROM blocks
            WHERE id=$1
               OR block_index::text=$1
          `, [value]);

        if (!result.rows.length) {
          return json(res, 404, {
            success: false,
            error:
              "Блок не найден"
          });
        }

        return json(res, 200, {
          success: true,
          block:
            result.rows[0]
        });
      }

      // ======================================================
      // VERIFY BLOCKCHAIN
      // ======================================================

      if (
        req.method === "GET" &&
        pathname === "/api/chain/verify"
      ) {
        const result =
          await pool.query(`
            SELECT *
            FROM blocks
            ORDER BY block_index ASC
          `);

        const blocks =
          result.rows;

        const errors = [];

        for (
          let i = 0;
          i < blocks.length;
          i++
        ) {
          const block =
            blocks[i];

          const recalculated =
            calculateBlockHash({
              index:
                Number(
                  block.block_index
                ),
              previous_hash:
                block.previous_hash,
              timestamp:
                new Date(
                  block.timestamp
                ).toISOString(),
              miner:
                block.miner,
              transaction_count:
                block.transaction_count,
              merkle_root:
                block.merkle_root
            });

          if (
            recalculated !==
            block.hash
          ) {
            errors.push({
              block:
                Number(
                  block.block_index
                ),
              error:
                "Invalid block hash"
            });
          }

          if (i > 0) {
            const previous =
              blocks[i - 1];

            if (
              block.previous_hash !==
              previous.hash
            ) {
              errors.push({
                block:
                  Number(
                    block.block_index
                  ),
                error:
                  "Invalid previous hash"
              });
            }

            if (
              Number(
                block.block_index
              ) !==
              Number(
                previous.block_index
              ) + 1
            ) {
              errors.push({
                block:
                  Number(
                    block.block_index
                  ),
                error:
                  "Invalid block sequence"
              });
            }
          }
        }

        return json(res, 200, {
          success: true,
          valid:
            errors.length === 0,
          blocks:
            blocks.length,
          errors
        });
      }

      // ======================================================
      // ECONOMY
      // ======================================================

      if (
        req.method === "GET" &&
        pathname === "/api/economy"
      ) {
        const supply =
          await pool.query(`
            SELECT COALESCE(
              SUM(balance),0
            ) AS total
            FROM wallets
          `);

        return json(res, 200, {
          success: true,
          symbol: "SLX",
          network: "SLX Testnet",
          maxSupply:
            MAX_SUPPLY,
          circulatingSupply:
            Number(
              supply.rows[0].total
            ),
          faucetAmount:
            FAUCET_AMOUNT,
          transferFee:
            TRANSFER_FEE
        });
      }

      // ======================================================
      // 404
      // ======================================================

      return json(res, 404, {
        success: false,
        error: "Not found"
      });

    } catch (error) {
      console.error(
        "SERVER ERROR:",
        error
      );

      return json(res, 500, {
        success: false,
        error:
          "Внутренняя ошибка сервера"
      });
    }
  });

// ============================================================
// START
// ============================================================

async function start() {
  try {
    await initDatabase();

    server.listen(
      PORT,
      () => {
        console.log(
          `SLX Network v${NETWORK_VERSION} running on port ${PORT}`
        );
      }
    );
  } catch (error) {
    console.error(
      "DATABASE ERROR:",
      error
    );

    process.exit(1);
  }
}

start();