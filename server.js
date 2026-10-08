// ============================================================
// SLX NETWORK v1.9.0
// SIMPLE TESTNET
// Без Ed25519 / publicKey / подписей
// ============================================================

const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { Pool } = require("pg");

const PORT = Number(process.env.PORT || 3000);

const NETWORK_VERSION = "1.9.0";
const NETWORK_ID = "SLX-TESTNET-1";

const MAX_SUPPLY = 21000000;
const INITIAL_BALANCE = 1000;
const FAUCET_AMOUNT = 10;
const TRANSFER_FEE = 0.1;

const SESSION_TTL = 7 * 24 * 60 * 60 * 1000;
const FAUCET_COOLDOWN = 24 * 60 * 60 * 1000;
const MAX_BODY = 1024 * 1024;

const sessions = new Map();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false,
  max: 10
});

// ============================================================
// HELPERS
// ============================================================

function send(res, status, data, type = "application/json") {
  res.writeHead(status, {
    "Content-Type": type,
    "Cache-Control": "no-store",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS"
  });

  if (type === "application/json") {
    res.end(JSON.stringify(data));
  } else {
    res.end(data);
  }
}

function json(res, status, data) {
  send(res, status, data);
}

function error(res, status, message) {
  json(res, status, {
    ok: false,
    message
  });
}

function randomHex(bytes = 16) {
  return crypto.randomBytes(bytes).toString("hex").toUpperCase();
}

function makeAddress() {
  return "SLXC" + randomHex(16);
}

function makeRecoveryCode() {
  return crypto.randomBytes(6).toString("hex").toUpperCase();
}

function hashPassword(password) {
  return crypto
    .createHash("sha256")
    .update(String(password))
    .digest("hex");
}

function hashText(text) {
  return crypto
    .createHash("sha256")
    .update(String(text))
    .digest("hex");
}

function makeToken() {
  return crypto.randomBytes(32).toString("hex");
}

function validUsername(username) {
  return /^[a-zA-Z0-9_]{3,32}$/.test(username);
}

function validAddress(address) {
  return /^SLXC[A-F0-9]{32}$/.test(address);
}

function validAmount(value) {
  const n = Number(value);

  return Number.isFinite(n) &&
    n > 0 &&
    n <= MAX_SUPPLY &&
    Math.round(n * 100000000) === n * 100000000;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";

    req.on("data", chunk => {
      body += chunk;

      if (body.length > MAX_BODY) {
        reject(new Error("Request too large"));
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

  return header.slice(7);
}

function getSession(req) {
  const token = getToken(req);

  if (!token) return null;

  const session = sessions.get(token);

  if (!session) return null;

  if (Date.now() > session.expires) {
    sessions.delete(token);
    return null;
  }

  return {
    token,
    ...session
  };
}

function requireAuth(req, res) {
  const session = getSession(req);

  if (!session) {
    error(res, 401, "Сессия истекла или пользователь не авторизован.");
    return null;
  }

  return session;
}

function createSession(userId) {
  const token = makeToken();

  sessions.set(token, {
    userId,
    expires: Date.now() + SESSION_TTL
  });

  return token;
}

async function totalSupply(client) {
  const result = await client.query(`
    SELECT COALESCE(SUM(balance), 0) AS total
    FROM wallets
  `);

  return Number(result.rows[0].total || 0);
}

// ============================================================
// DATABASE
// ============================================================

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      recovery_code_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS wallets (
      id SERIAL PRIMARY KEY,
      owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      address TEXT UNIQUE NOT NULL,
      balance NUMERIC(30,8) NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS transactions (
      id SERIAL PRIMARY KEY,
      wallet_id INTEGER REFERENCES wallets(id) ON DELETE SET NULL,
      type TEXT NOT NULL,
      amount NUMERIC(30,8) NOT NULL,
      from_wallet TEXT,
      to_wallet TEXT,
      fee NUMERIC(30,8) DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS blocks (
      id SERIAL PRIMARY KEY,
      block_index INTEGER UNIQUE NOT NULL,
      previous_hash TEXT NOT NULL,
      hash TEXT NOT NULL,
      timestamp TIMESTAMPTZ DEFAULT NOW(),
      miner TEXT,
      transaction_count INTEGER DEFAULT 0,
      merkle_root TEXT
    );

    CREATE TABLE IF NOT EXISTS faucet_claims (
      wallet_id INTEGER PRIMARY KEY REFERENCES wallets(id) ON DELETE CASCADE,
      last_claim_at TIMESTAMPTZ NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_wallet_owner
      ON wallets(owner_id);

    CREATE INDEX IF NOT EXISTS idx_tx_wallet
      ON transactions(wallet_id);

    CREATE INDEX IF NOT EXISTS idx_blocks_index
      ON blocks(block_index);
  `);

  const blockCheck = await pool.query(
    `SELECT COUNT(*)::int AS count FROM blocks`
  );

  if (blockCheck.rows[0].count === 0) {
    const genesisData = "SLX-GENESIS-" + NETWORK_ID;

    const hash = crypto
      .createHash("sha256")
      .update(genesisData)
      .digest("hex");

    await pool.query(`
      INSERT INTO blocks
      (block_index, previous_hash, hash, miner, transaction_count, merkle_root)
      VALUES (0, '0', $1, 'SLX-GENESIS', 0, $2)
    `, [hash, hash]);
  }

  console.log("SLX database initialized");
}

// ============================================================
// BLOCKCHAIN
// ============================================================

async function createBlock(client, miner = "SLX-NETWORK") {
  const last = await client.query(`
    SELECT *
    FROM blocks
    ORDER BY block_index DESC
    LIMIT 1
  `);

  const previous = last.rows[0];

  const blockIndex = Number(previous.block_index) + 1;
  const timestamp = new Date().toISOString();

  const data = JSON.stringify({
    blockIndex,
    previousHash: previous.hash,
    timestamp,
    miner
  });

  const hash = crypto
    .createHash("sha256")
    .update(data)
    .digest("hex");

  await client.query(`
    INSERT INTO blocks
    (block_index, previous_hash, hash, timestamp, miner,
     transaction_count, merkle_root)
    VALUES ($1,$2,$3,$4,$5,0,$6)
  `, [
    blockIndex,
    previous.hash,
    hash,
    timestamp,
    miner,
    hash
  ]);

  return {
    blockIndex,
    hash
  };
}

// ============================================================
// AUTH REGISTER
// ============================================================

async function register(req, res) {
  const body = await readBody(req);

  const username = String(body.username || "").trim();
  const password = String(body.password || "");

  if (!validUsername(username)) {
    return error(
      res,
      400,
      "Имя пользователя: 3–32 символа, только буквы, цифры и _."
    );
  }

  if (password.length < 6) {
    return error(
      res,
      400,
      "Пароль должен содержать минимум 6 символов."
    );
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const exists = await client.query(
      `SELECT id FROM users WHERE LOWER(username)=LOWER($1)`,
      [username]
    );

    if (exists.rows.length) {
      await client.query("ROLLBACK");
      return error(res, 409, "Такой пользователь уже существует.");
    }

    const currentSupply = await totalSupply(client);

    if (currentSupply + INITIAL_BALANCE > MAX_SUPPLY) {
      await client.query("ROLLBACK");
      return error(res, 400, "Недостаточно свободного предложения SLX.");
    }

    const recoveryCode = makeRecoveryCode();

    const userResult = await client.query(`
      INSERT INTO users
      (username,password_hash,recovery_code_hash)
      VALUES ($1,$2,$3)
      RETURNING id,username,created_at
    `, [
      username,
      hashPassword(password),
      hashText(recoveryCode)
    ]);

    const user = userResult.rows[0];

    const address = makeAddress();

    const walletResult = await client.query(`
      INSERT INTO wallets
      (owner_id,address,balance)
      VALUES ($1,$2,$3)
      RETURNING *
    `, [
      user.id,
      address,
      INITIAL_BALANCE
    ]);

    const wallet = walletResult.rows[0];

    await client.query("COMMIT");

    const token = createSession(user.id);

    json(res, 201, {
      ok: true,
      token,
      user,
      wallet,
      recoveryCode
    });

  } catch (err) {
    try {
      await client.query("ROLLBACK");
    } catch {}

    console.error(err);

    error(res, 500, "Ошибка регистрации.");
  } finally {
    client.release();
  }
}

// ============================================================
// LOGIN
// ============================================================

async function login(req, res) {
  const body = await readBody(req);

  const username = String(body.username || "").trim();
  const password = String(body.password || "");

  const result = await pool.query(`
    SELECT *
    FROM users
    WHERE LOWER(username)=LOWER($1)
    LIMIT 1
  `, [username]);

  if (!result.rows.length) {
    return error(res, 401, "Неверный логин или пароль.");
  }

  const user = result.rows[0];

  if (
    hashPassword(password) !==
    user.password_hash
  ) {
    return error(res, 401, "Неверный логин или пароль.");
  }

  const token = createSession(user.id);

  delete user.password_hash;
  delete user.recovery_code_hash;

  json(res, 200, {
    ok: true,
    token,
    user
  });
}

// ============================================================
// ME
// ============================================================

async function me(req, res) {
  const session = requireAuth(req, res);
  if (!session) return;

  const userResult = await pool.query(`
    SELECT id,username,created_at
    FROM users
    WHERE id=$1
  `, [session.userId]);

  if (!userResult.rows.length) {
    return error(res, 404, "Пользователь не найден.");
  }

  const walletResult = await pool.query(`
    SELECT *
    FROM wallets
    WHERE owner_id=$1
    ORDER BY id ASC
  `, [session.userId]);

  json(res, 200, {
    ok: true,
    user: userResult.rows[0],
    wallets: walletResult.rows
  });
}

// ============================================================
// WALLETS
// ============================================================

async function wallets(req, res) {
  const session = requireAuth(req, res);
  if (!session) return;

  const result = await pool.query(`
    SELECT *
    FROM wallets
    WHERE owner_id=$1
    ORDER BY id ASC
  `, [session.userId]);

  json(res, 200, {
    ok: true,
    wallets: result.rows
  });
}

async function createWallet(req, res) {
  const session = requireAuth(req, res);
  if (!session) return;

  const address = makeAddress();

  const result = await pool.query(`
    INSERT INTO wallets
    (owner_id,address,balance)
    VALUES ($1,$2,0)
    RETURNING *
  `, [
    session.userId,
    address
  ]);

  json(res, 201, {
    ok: true,
    wallet: result.rows[0]
  });
}

async function selectWallet(req, res) {
  const session = requireAuth(req, res);
  if (!session) return;

  const body = await readBody(req);

  const walletId = Number(body.walletId);

  const result = await pool.query(`
    SELECT *
    FROM wallets
    WHERE id=$1 AND owner_id=$2
  `, [
    walletId,
    session.userId
  ]);

  if (!result.rows.length) {
    return error(res, 404, "Кошелёк не найден.");
  }

  json(res, 200, {
    ok: true,
    wallet: result.rows[0]
  });
}

async function walletDetails(req, res, walletId) {
  const session = requireAuth(req, res);
  if (!session) return;

  const walletResult = await pool.query(`
    SELECT *
    FROM wallets
    WHERE id=$1 AND owner_id=$2
  `, [
    walletId,
    session.userId
  ]);

  if (!walletResult.rows.length) {
    return error(res, 404, "Кошелёк не найден.");
  }

  const wallet = walletResult.rows[0];

  const txResult = await pool.query(`
    SELECT *
    FROM transactions
    WHERE wallet_id=$1
    ORDER BY created_at DESC
    LIMIT 100
  `, [wallet.id]);

  json(res, 200, {
    ok: true,
    wallet: {
      ...wallet,
      transactions: txResult.rows
    }
  });
}

// ============================================================
// SEND
// ============================================================

async function sendSLX(req, res) {
  const session = requireAuth(req, res);
  if (!session) return;

  const body = await readBody(req);

  const from = String(body.from || "").toUpperCase();
  const to = String(body.to || "").toUpperCase();
  const amount = Number(body.amount);

  if (!validAddress(from)) {
    return error(res, 400, "Некорректный адрес отправителя.");
  }

  if (!validAddress(to)) {
    return error(res, 400, "Некорректный адрес получателя.");
  }

  if (from === to) {
    return error(res, 400, "Нельзя отправить самому себе.");
  }

  if (!validAmount(amount)) {
    return error(res, 400, "Некорректная сумма.");
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const senderResult = await client.query(`
      SELECT *
      FROM wallets
      WHERE address=$1
      AND owner_id=$2
      FOR UPDATE
    `, [
      from,
      session.userId
    ]);

    if (!senderResult.rows.length) {
      await client.query("ROLLBACK");
      return error(res, 403, "Этот кошелёк вам не принадлежит.");
    }

    const sender = senderResult.rows[0];

    const recipientResult = await client.query(`
      SELECT *
      FROM wallets
      WHERE address=$1
      LIMIT 1
    `, [to]);

    if (!recipientResult.rows.length) {
      await client.query("ROLLBACK");
      return error(res, 404, "Кошелёк получателя не найден.");
    }

    const recipient = recipientResult.rows[0];

    const total = amount + TRANSFER_FEE;

    if (Number(sender.balance) < total) {
      await client.query("ROLLBACK");

      return error(
        res,
        400,
        `Недостаточно SLX. Нужно ${total.toFixed(8)} SLX.`
      );
    }

    await client.query(`
      UPDATE wallets
      SET balance=balance-$1
      WHERE id=$2
    `, [
      total,
      sender.id
    ]);

    await client.query(`
      UPDATE wallets
      SET balance=balance+$1
      WHERE id=$2
    `, [
      amount,
      recipient.id
    ]);

    await client.query(`
      INSERT INTO transactions
      (wallet_id,type,amount,from_wallet,to_wallet,fee)
      VALUES ($1,'SEND',$2,$3,$4,$5)
    `, [
      sender.id,
      amount,
      from,
      to,
      TRANSFER_FEE
    ]);

    await client.query(`
      INSERT INTO transactions
      (wallet_id,type,amount,from_wallet,to_wallet,fee)
      VALUES ($1,'RECEIVE',$2,$3,$4,0)
    `, [
      recipient.id,
      amount,
      from,
      to
    ]);

    const block = await createBlock(
      client,
      from
    );

    await client.query("COMMIT");

    json(res, 200, {
      ok: true,
      message: "Транзакция успешно отправлена.",
      amount,
      fee: TRANSFER_FEE,
      block
    });

  } catch (err) {

    try {
      await client.query("ROLLBACK");
    } catch {}

    console.error(err);

    error(res, 500, "Ошибка транзакции.");

  } finally {
    client.release();
  }
}

// ============================================================
// FAUCET
// ============================================================

async function faucet(req, res) {
  const session = requireAuth(req, res);
  if (!session) return;

  const body = await readBody(req);

  const walletId = Number(body.walletId);

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const walletResult = await client.query(`
      SELECT *
      FROM wallets
      WHERE id=$1 AND owner_id=$2
      FOR UPDATE
    `, [
      walletId,
      session.userId
    ]);

    if (!walletResult.rows.length) {
      await client.query("ROLLBACK");
      return error(res, 404, "Кошелёк не найден.");
    }

    const wallet = walletResult.rows[0];

    const claim = await client.query(`
      SELECT *
      FROM faucet_claims
      WHERE wallet_id=$1
    `, [wallet.id]);

    if (claim.rows.length) {
      const last =
        new Date(claim.rows[0].last_claim_at).getTime();

      const remaining =
        FAUCET_COOLDOWN -
        (Date.now() - last);

      if (remaining > 0) {
        const hours =
          Math.ceil(remaining / 3600000);

        await client.query("ROLLBACK");

        return error(
          res,
          429,
          `Faucet будет доступен примерно через ${hours} ч.`
        );
      }
    }

    const supply = await totalSupply(client);

    if (supply + FAUCET_AMOUNT > MAX_SUPPLY) {
      await client.query("ROLLBACK");
      return error(res, 400, "Недостаточно предложения SLX.");
    }

    await client.query(`
      UPDATE wallets
      SET balance=balance+$1
      WHERE id=$2
    `, [
      FAUCET_AMOUNT,
      wallet.id
    ]);

    await client.query(`
      INSERT INTO faucet_claims
      (wallet_id,last_claim_at)
      VALUES ($1,NOW())
      ON CONFLICT(wallet_id)
      DO UPDATE SET last_claim_at=NOW()
    `, [wallet.id]);

    await client.query(`
      INSERT INTO transactions
      (wallet_id,type,amount,to_wallet,fee)
      VALUES ($1,'FAUCET',$2,$3,0)
    `, [
      wallet.id,
      FAUCET_AMOUNT,
      wallet.address
    ]);

    const block = await createBlock(
      client,
      "SLX-FAUCET"
    );

    await client.query("COMMIT");

    json(res, 200, {
      ok: true,
      message: `Получено +${FAUCET_AMOUNT} SLX.`,
      amount: FAUCET_AMOUNT,
      block
    });

  } catch (err) {

    try {
      await client.query("ROLLBACK");
    } catch {}

    console.error(err);

    error(res, 500, "Ошибка Faucet.");

  } finally {
    client.release();
  }
}

// ============================================================
// STATUS
// ============================================================

async function status(req, res) {

  const blocks = await pool.query(`
    SELECT COUNT(*)::int AS count
    FROM blocks
  `);

  const wallets = await pool.query(`
    SELECT COUNT(*)::int AS count
    FROM wallets
  `);

  const lastBlock = await pool.query(`
    SELECT *
    FROM blocks
    ORDER BY block_index DESC
    LIMIT 1
  `);

  json(res, 200, {
    ok: true,
    version: NETWORK_VERSION,
    networkVersion: NETWORK_VERSION,
    networkId: NETWORK_ID,
    status: "online",
    blockHeight:
      lastBlock.rows[0]?.block_index ?? 0,
    blocks: blocks.rows[0].count,
    wallets: wallets.rows[0].count
  });
}

// ============================================================
// ECONOMY
// ============================================================

async function economy(req, res) {

  const supply = await pool.query(`
    SELECT COALESCE(SUM(balance),0) AS total
    FROM wallets
  `);

  const wallets = await pool.query(`
    SELECT COUNT(*)::int AS count
    FROM wallets
  `);

  json(res, 200, {
    ok: true,
    maxSupply: MAX_SUPPLY,
    maximumSupply: MAX_SUPPLY,
    circulatingSupply: Number(
      supply.rows[0].total || 0
    ),
    circulating: Number(
      supply.rows[0].total || 0
    ),
    wallets: wallets.rows[0].count,
    walletCount: wallets.rows[0].count,
    faucetAmount: FAUCET_AMOUNT,
    transferFee: TRANSFER_FEE
  });
}

// ============================================================
// BLOCKS
// ============================================================

async function blocks(req, res) {

  const result = await pool.query(`
    SELECT *
    FROM blocks
    ORDER BY block_index DESC
    LIMIT 100
  `);

  json(res, 200, {
    ok: true,
    blocks: result.rows
  });
}

// ============================================================
// CHAIN VERIFY
// ============================================================

async function verifyChain(req, res) {

  const result = await pool.query(`
    SELECT *
    FROM blocks
    ORDER BY block_index ASC
  `);

  const chain = result.rows;

  if (!chain.length) {
    return json(res, 200, {
      ok: true,
      valid: true,
      message: "Blockchain пуст."
    });
  }

  for (let i = 0; i < chain.length; i++) {

    const block = chain[i];

    if (i === 0) {
      if (block.previous_hash !== "0") {
        return json(res, 200, {
          ok: true,
          valid: false,
          message: "Genesis block invalid."
        });
      }

      continue;
    }

    const previous = chain[i - 1];

    if (
      Number(block.block_index) !==
      Number(previous.block_index) + 1
    ) {
      return json(res, 200, {
        ok: true,
        valid: false,
        message: "Block index broken."
      });
    }

    if (
      block.previous_hash !==
      previous.hash
    ) {
      return json(res, 200, {
        ok: true,
        valid: false,
        message: "Previous hash mismatch."
      });
    }
  }

  json(res, 200, {
    ok: true,
    valid: true,
    message: "Blockchain корректен.",
    blocks: chain.length
  });
}

// ============================================================
// RECOVERY
// ============================================================

async function recoveryReset(req, res) {

  const body = await readBody(req);

  const username =
    String(body.username || "").trim();

  const recoveryCode =
    String(body.recoveryCode || "")
      .trim()
      .toUpperCase();

  const newPassword =
    String(body.newPassword || "");

  if (newPassword.length < 6) {
    return error(
      res,
      400,
      "Новый пароль должен содержать минимум 6 символов."
    );
  }

  const result = await pool.query(`
    SELECT *
    FROM users
    WHERE LOWER(username)=LOWER($1)
  `, [username]);

  if (!result.rows.length) {
    return error(
      res,
      400,
      "Неверные данные восстановления."
    );
  }

  const user = result.rows[0];

  if (
    hashText(recoveryCode) !==
    user.recovery_code_hash
  ) {
    return error(
      res,
      400,
      "Неверный Recovery Code."
    );
  }

  await pool.query(`
    UPDATE users
    SET password_hash=$1
    WHERE id=$2
  `, [
    hashPassword(newPassword),
    user.id
  ]);

  for (const [key, session] of sessions) {
    if (session.userId === user.id) {
      sessions.delete(key);
    }
  }

  const token = createSession(user.id);

  json(res, 200, {
    ok: true,
    message: "Пароль восстановлен.",
    token
  });
}

// ============================================================
// CHANGE PASSWORD
// ============================================================

async function changePassword(req, res) {

  const session = requireAuth(req, res);
  if (!session) return;

  const body = await readBody(req);

  const oldPassword =
    String(body.oldPassword || "");

  const newPassword =
    String(body.newPassword || "");

  if (newPassword.length < 6) {
    return error(
      res,
      400,
      "Новый пароль должен содержать минимум 6 символов."
    );
  }

  const result = await pool.query(`
    SELECT *
    FROM users
    WHERE id=$1
  `, [session.userId]);

  const user = result.rows[0];

  if (
    hashPassword(oldPassword) !==
    user.password_hash
  ) {
    return error(
      res,
      400,
      "Неверный текущий пароль."
    );
  }

  await pool.query(`
    UPDATE users
    SET password_hash=$1
    WHERE id=$2
  `, [
    hashPassword(newPassword),
    user.id
  ]);

  for (const [key, value] of sessions) {
    if (value.userId === user.id) {
      sessions.delete(key);
    }
  }

  const newToken =
    createSession(user.id);

  json(res, 200, {
    ok: true,
    message: "Пароль изменён.",
    token: newToken
  });
}

// ============================================================
// LOGOUT
// ============================================================

async function logout(req, res) {

  const token = getToken(req);

  if (token) {
    sessions.delete(token);
  }

  json(res, 200, {
    ok: true,
    message: "Вы вышли из аккаунта."
  });
}

// ============================================================
// STATIC FILE
// ============================================================

function serveIndex(req, res) {

  const file =
    path.join(__dirname, "index.html");

  fs.readFile(file, (err, data) => {

    if (err) {
      return error(
        res,
        500,
        "index.html не найден."
      );
    }

    send(
      res,
      200,
      data,
      "text/html; charset=utf-8"
    );
  });
}

// ============================================================
// ROUTER
// ============================================================

async function router(req, res) {

  if (req.method === "OPTIONS") {
    return send(res, 204, "");
  }

  const url =
    new URL(
      req.url,
      `http://${req.headers.host}`
    );

  const pathname = url.pathname;

  try {

    if (
      req.method === "GET" &&
      pathname === "/"
    ) {
      return serveIndex(req, res);
    }

    if (
      req.method === "POST" &&
      pathname === "/api/auth/register"
    ) {
      return await register(req, res);
    }

    if (
      req.method === "POST" &&
      pathname === "/api/auth/login"
    ) {
      return await login(req, res);
    }

    if (
      req.method === "GET" &&
      pathname === "/api/auth/me"
    ) {
      return await me(req, res);
    }

    if (
      req.method === "POST" &&
      pathname === "/api/auth/logout"
    ) {
      return await logout(req, res);
    }

    if (
      req.method === "POST" &&
      pathname === "/api/auth/recovery/reset"
    ) {
      return await recoveryReset(req, res);
    }

    if (
      req.method === "POST" &&
      pathname === "/api/auth/password/change"
    ) {
      return await changePassword(req, res);
    }

    if (
      req.method === "GET" &&
      pathname === "/api/wallets"
    ) {
      return await wallets(req, res);
    }

    if (
      req.method === "POST" &&
      pathname === "/api/wallet/create"
    ) {
      return await createWallet(req, res);
    }

    if (
      req.method === "POST" &&
      pathname === "/api/wallet/select"
    ) {
      return await selectWallet(req, res);
    }

    if (
      req.method === "GET" &&
      pathname.startsWith("/api/wallet/")
    ) {
      const id =
        pathname.split("/").pop();

      return await walletDetails(
        req,
        res,
        Number(id)
      );
    }

    if (
      req.method === "POST" &&
      pathname === "/api/send"
    ) {
      return await sendSLX(req, res);
    }

    if (
      req.method === "POST" &&
      pathname === "/api/faucet"
    ) {
      return await faucet(req, res);
    }

    if (
      req.method === "GET" &&
      pathname === "/api/status"
    ) {
      return await status(req, res);
    }

    if (
      req.method === "GET" &&
      pathname === "/api/economy"
    ) {
      return await economy(req, res);
    }

    if (
      req.method === "GET" &&
      pathname === "/api/blocks"
    ) {
      return await blocks(req, res);
    }

    if (
      req.method === "GET" &&
      pathname === "/api/chain/verify"
    ) {
      return await verifyChain(req, res);
    }

    return error(res, 404, "Route not found.");

  } catch (err) {

    console.error(err);

    error(
      res,
      500,
      "Внутренняя ошибка сервера."
    );
  }
}

// ============================================================
// START
// ============================================================

async function start() {

  try {

    await initDatabase();

    const server =
      http.createServer(router);

    server.listen(
      PORT,
      "0.0.0.0",
      () => {
        console.log(
          `SLX Network v${NETWORK_VERSION}`
        );

        console.log(
          `Network: ${NETWORK_ID}`
        );

        console.log(
          `Port: ${PORT}`
        );
      }
    );

  } catch (err) {

    console.error(
      "SLX startup error:",
      err
    );

    process.exit(1);
  }
}

start();
