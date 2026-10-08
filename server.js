// ============================================================
// SLX NETWORK v1.9
// Cryptographic Testnet Prototype
// Ed25519 + Nonce + Signed Transactions
// ============================================================

const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { webcrypto } = require("node:crypto");
const { Pool } = require("pg");

const subtle = webcrypto.subtle;

const PORT = Number(process.env.PORT || 3000);
const NETWORK_VERSION = "1.9.0";
const NETWORK_ID = "SLX-TESTNET-1";

const MAX_SUPPLY = "21000000";
const INITIAL_BALANCE = "1000";
const FAUCET_AMOUNT = "10";
const TRANSFER_FEE = "0.1";
const FAUCET_COOLDOWN_MS = 24 * 60 * 60 * 1000;

const MAX_BODY_SIZE = 1024 * 1024;
const SESSION_TTL = 7 * 24 * 60 * 60 * 1000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false,
  max: 10
});

const sessions = new Map();

const PUBLIC_DIR = __dirname;

function send(res, status, data, headers = {}) {
  const body =
    typeof data === "string"
      ? data
      : JSON.stringify(data);

  res.writeHead(status, {
    "Content-Type":
      typeof data === "string"
        ? "text/html; charset=utf-8"
        : "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    ...headers
  });

  res.end(body);
}

function json(res, status, data) {
  send(res, status, data);
}

function error(res, status, message) {
  json(res, status, {
    ok: false,
    error: message
  });
}

function randomHex(bytes = 32) {
  return crypto.randomBytes(bytes).toString("hex").toUpperCase();
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16);

  const derived = crypto.scryptSync(
    password,
    salt,
    64
  );

  return (
    "scrypt$" +
    salt.toString("hex") +
    "$" +
    derived.toString("hex")
  );
}

function verifyPassword(password, stored) {
  try {
    const parts = stored.split("$");

    if (parts.length !== 3) return false;

    const salt = Buffer.from(parts[1], "hex");
    const expected = Buffer.from(parts[2], "hex");

    const actual = crypto.scryptSync(
      password,
      salt,
      64
    );

    return crypto.timingSafeEqual(
      expected,
      actual
    );
  } catch {
    return false;
  }
}

function hashRecovery(code) {
  return crypto
    .createHash("sha256")
    .update(code)
    .digest("hex");
}

function generateRecoveryCode() {
  return randomHex(6);
}

function normalizeUsername(username) {
  return String(username || "")
    .trim()
    .toLowerCase();
}

function isUsernameValid(username) {
  return /^[a-zA-Z0-9_]{3,24}$/.test(username);
}

function isPasswordValid(password) {
  return (
    typeof password === "string" &&
    password.length >= 8 &&
    password.length <= 128
  );
}

function isPublicKeyValid(publicKey) {
  return (
    typeof publicKey === "string" &&
    /^[0-9a-fA-F]{64}$/.test(publicKey)
  );
}

function isSignatureValid(signature) {
  return (
    typeof signature === "string" &&
    /^[0-9a-fA-F]{128}$/.test(signature)
  );
}

function isAddressValid(address) {
  return (
    typeof address === "string" &&
    /^SLXC[A-F0-9]{32}$/.test(address)
  );
}

function deriveAddress(publicKeyHex) {
  return (
    "SLXC" +
    crypto
      .createHash("sha256")
      .update(
        Buffer.from(publicKeyHex, "hex")
      )
      .digest("hex")
      .slice(0, 32)
      .toUpperCase()
  );
}

function isAmountValid(value) {
  const n = Number(value);

  if (!Number.isFinite(n)) return false;
  if (n <= 0) return false;
  if (n > 1000000000) return false;

  const text = String(value);

  if (
    text.includes(".") &&
    text.split(".")[1].length > 8
  ) {
    return false;
  }

  return true;
}

function amountNumber(value) {
  return Number(Number(value).toFixed(8));
}

function cleanupSessions() {
  const now = Date.now();

  for (const [token, session] of sessions) {
    if (session.expiresAt <= now) {
      sessions.delete(token);
    }
  }
}

setInterval(cleanupSessions, 60 * 1000).unref();

function createSession(userId) {
  const token = crypto.randomBytes(32).toString("hex");

  sessions.set(token, {
    userId,
    expiresAt: Date.now() + SESSION_TTL
  });

  return token;
}

function getUserId(req) {
  const header = req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return null;
  }

  const token = header.slice(7);

  const session = sessions.get(token);

  if (!session) return null;

  if (session.expiresAt <= Date.now()) {
    sessions.delete(token);
    return null;
  }

  session.expiresAt =
    Date.now() + SESSION_TTL;

  return session.userId;
}

function getToken(req) {
  const header = req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return null;
  }

  return header.slice(7);
}

async function body(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    let size = 0;

    req.on("data", chunk => {
      size += chunk.length;

      if (size > MAX_BODY_SIZE) {
        reject(new Error("BODY_TOO_LARGE"));
        req.destroy();
        return;
      }

      data += chunk.toString();
    });

    req.on("end", () => {
      if (!data) {
        resolve({});
        return;
      }

      try {
        resolve(JSON.parse(data));
      } catch {
        reject(new Error("INVALID_JSON"));
      }
    });

    req.on("error", reject);
  });
}

function canonicalTransaction(tx) {
  return JSON.stringify({
    version: 1,
    network: NETWORK_ID,
    from: tx.from,
    to: tx.to,
    amount: Number(tx.amount),
    fee: Number(tx.fee),
    nonce: Number(tx.nonce),
    timestamp: Number(tx.timestamp)
  });
}

async function verifyEd25519(
  publicKeyHex,
  signatureHex,
  message
) {
  try {
    const publicKey = await subtle.importKey(
      "raw",
      Buffer.from(publicKeyHex, "hex"),
      {
        name: "Ed25519"
      },
      false,
      ["verify"]
    );

    return await subtle.verify(
      {
        name: "Ed25519"
      },
      publicKey,
      Buffer.from(signatureHex, "hex"),
      Buffer.from(message, "utf8")
    );
  } catch {
    return false;
  }
}

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      recovery_code_hash TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS wallets (
      id SERIAL PRIMARY KEY,
      owner_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      address TEXT UNIQUE NOT NULL,
      balance NUMERIC(30,8) NOT NULL DEFAULT 0,
      public_key TEXT,
      nonce BIGINT NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS transactions (
      id SERIAL PRIMARY KEY,
      wallet_id INTEGER REFERENCES wallets(id),
      type TEXT NOT NULL,
      amount NUMERIC(30,8) NOT NULL,
      from_wallet TEXT,
      to_wallet TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      fee NUMERIC(30,8) DEFAULT 0,
      nonce BIGINT,
      public_key TEXT,
      signature TEXT
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS blocks (
      id SERIAL PRIMARY KEY,
      block_index BIGINT UNIQUE NOT NULL,
      previous_hash TEXT NOT NULL,
      hash TEXT NOT NULL,
      timestamp BIGINT NOT NULL,
      miner TEXT,
      transaction_count INTEGER DEFAULT 0,
      merkle_root TEXT
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
      wallet_id INTEGER PRIMARY KEY REFERENCES wallets(id) ON DELETE CASCADE,
      last_claim_at TIMESTAMPTZ NOT NULL
    )
  `);

  // Migrations for v1.9
  await pool.query(`
    ALTER TABLE wallets
    ADD COLUMN IF NOT EXISTS public_key TEXT
  `);

  await pool.query(`
    ALTER TABLE wallets
    ADD COLUMN IF NOT EXISTS nonce BIGINT NOT NULL DEFAULT 0
  `);

  await pool.query(`
    ALTER TABLE transactions
    ADD COLUMN IF NOT EXISTS nonce BIGINT
  `);

  await pool.query(`
    ALTER TABLE transactions
    ADD COLUMN IF NOT EXISTS public_key TEXT
  `);

  await pool.query(`
    ALTER TABLE transactions
    ADD COLUMN IF NOT EXISTS signature TEXT
  `);

  const states = [
    ["max_supply", MAX_SUPPLY],
    ["transfer_fee", TRANSFER_FEE],
    ["faucet_amount", FAUCET_AMOUNT],
    ["network_version", NETWORK_VERSION],
    ["network_id", NETWORK_ID]
  ];

  for (const [key, value] of states) {
    await pool.query(
      `
      INSERT INTO network_state(key,value)
      VALUES($1,$2)
      ON CONFLICT(key)
      DO UPDATE SET value=EXCLUDED.value
      `,
      [key, value]
    );
  }

  const genesis = await pool.query(`
    SELECT id FROM blocks LIMIT 1
  `);

  if (genesis.rowCount === 0) {
    const timestamp = Date.now();

    const hash = crypto
      .createHash("sha256")
      .update(
        `SLX-GENESIS-${NETWORK_ID}-${timestamp}`
      )
      .digest("hex");

    await pool.query(
      `
      INSERT INTO blocks(
        block_index,
        previous_hash,
        hash,
        timestamp,
        miner,
        transaction_count,
        merkle_root
      )
      VALUES(0,$1,$2,$3,$4,0,$5)
      `,
      [
        "0".repeat(64),
        hash,
        timestamp,
        "SLX",
        "0".repeat(64)
      ]
    );
  }
}

async function getUser(userId) {
  const result = await pool.query(
    `
    SELECT id, username, created_at
    FROM users
    WHERE id=$1
    `,
    [userId]
  );

  return result.rows[0] || null;
}

async function getWallets(userId) {
  const result = await pool.query(
    `
    SELECT
      id,
      address,
      balance,
      public_key,
      nonce,
      created_at
    FROM wallets
    WHERE owner_id=$1
    ORDER BY id ASC
    `,
    [userId]
  );

  return result.rows;
}

async function getTotalSupply(client = pool) {
  const result = await client.query(`
    SELECT COALESCE(
      SUM(balance),
      0
    )::numeric AS total
    FROM wallets
  `);

  return Number(result.rows[0].total);
}

async function createBlock(
  client,
  miner,
  transactionCount,
  merkleRoot
) {
  const last = await client.query(`
    SELECT
      block_index,
      hash
    FROM blocks
    ORDER BY block_index DESC
    LIMIT 1
    FOR UPDATE
  `);

  const previous =
    last.rows[0] || {
      block_index: -1,
      hash: "0".repeat(64)
    };

  const blockIndex =
    Number(previous.block_index) + 1;

  const timestamp = Date.now();

  const raw = [
    NETWORK_ID,
    blockIndex,
    previous.hash,
    timestamp,
    miner || "SLX",
    transactionCount,
    merkleRoot
  ].join("|");

  const hash = crypto
    .createHash("sha256")
    .update(raw)
    .digest("hex");

  await client.query(
    `
    INSERT INTO blocks(
      block_index,
      previous_hash,
      hash,
      timestamp,
      miner,
      transaction_count,
      merkle_root
    )
    VALUES($1,$2,$3,$4,$5,$6,$7)
    `,
    [
      blockIndex,
      previous.hash,
      hash,
      timestamp,
      miner || "SLX",
      transactionCount,
      merkleRoot
    ]
  );

  return {
    blockIndex,
    hash,
    previousHash: previous.hash,
    timestamp
  };
}

function merkleRoot(items) {
  if (!items.length) {
    return "0".repeat(64);
  }

  let level = items.map(x =>
    crypto
      .createHash("sha256")
      .update(x)
      .digest("hex")
  );

  while (level.length > 1) {
    const next = [];

    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right =
        level[i + 1] || left;

      next.push(
        crypto
          .createHash("sha256")
          .update(left + right)
          .digest("hex")
      );
    }

    level = next;
  }

  return level[0];
}

async function register(req, res) {
  const data = await body(req);

  const username = normalizeUsername(
    data.username
  );

  const password = data.password;
  const publicKey = String(
    data.publicKey || ""
  ).toUpperCase();

  if (!isUsernameValid(username)) {
    return error(
      res,
      400,
      "Username: 3-24 символа, только буквы, цифры и _"
    );
  }

  if (!isPasswordValid(password)) {
    return error(
      res,
      400,
      "Пароль должен содержать минимум 8 символов"
    );
  }

  if (!isPublicKeyValid(publicKey)) {
    return error(
      res,
      400,
      "Некорректный Ed25519 public key"
    );
  }

  const address = deriveAddress(
    publicKey
  );

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    await client.query(
      "SELECT pg_advisory_xact_lock(1988019)"
    );

    const exists = await client.query(
      `
      SELECT id
      FROM users
      WHERE username=$1
      `,
      [username]
    );

    if (exists.rowCount) {
      await client.query("ROLLBACK");

      return error(
        res,
        409,
        "Пользователь уже существует"
      );
    }

    const recoveryCode =
      generateRecoveryCode();

    const userResult =
      await client.query(
        `
        INSERT INTO users(
          username,
          password_hash,
          recovery_code_hash
        )
        VALUES($1,$2,$3)
        RETURNING id, username
        `,
        [
          username,
          hashPassword(password),
          hashRecovery(recoveryCode)
        ]
      );

    const user =
      userResult.rows[0];

    const totalSupply =
      await getTotalSupply(client);

    const initial =
      Number(INITIAL_BALANCE);

    if (
      totalSupply + initial >
      Number(MAX_SUPPLY)
    ) {
      await client.query("ROLLBACK");

      return error(
        res,
        503,
        "Достигнут лимит эмиссии SLX"
      );
    }

    const walletResult =
      await client.query(
        `
        INSERT INTO wallets(
          owner_id,
          address,
          balance,
          public_key,
          nonce
        )
        VALUES($1,$2,$3,$4,0)
        RETURNING *
        `,
        [
          user.id,
          address,
          INITIAL_BALANCE,
          publicKey
        ]
      );

    await client.query("COMMIT");

    const token =
      createSession(user.id);

    return json(res, 201, {
      ok: true,
      user: {
        id: user.id,
        username: user.username
      },
      wallet: walletResult.rows[0],
      recoveryCode,
      token,
      network: NETWORK_VERSION
    });
  } catch (e) {
    try {
      await client.query("ROLLBACK");
    } catch {}

    console.error(e);

    return error(
      res,
      500,
      "Ошибка регистрации"
    );
  } finally {
    client.release();
  }
}

async function login(req, res) {
  const data = await body(req);

  const username =
    normalizeUsername(data.username);

  const password = data.password;

  const result = await pool.query(
    `
    SELECT id, username, password_hash
    FROM users
    WHERE username=$1
    `,
    [username]
  );

  if (!result.rowCount) {
    return error(
      res,
      401,
      "Неверный логин или пароль"
    );
  }

  const user = result.rows[0];

  if (
    !verifyPassword(
      password,
      user.password_hash
    )
  ) {
    return error(
      res,
      401,
      "Неверный логин или пароль"
    );
  }

  const wallets =
    await getWallets(user.id);

  const token =
    createSession(user.id);

  return json(res, 200, {
    ok: true,
    token,
    user: {
      id: user.id,
      username: user.username
    },
    wallets,
    network: NETWORK_VERSION
  });
}

async function me(req, res) {
  const userId = getUserId(req);

  if (!userId) {
    return error(
      res,
      401,
      "Сессия недействительна"
    );
  }

  const user =
    await getUser(userId);

  const wallets =
    await getWallets(userId);

  return json(res, 200, {
    ok: true,
    user,
    wallets,
    network: NETWORK_VERSION
  });
}

async function createWallet(req, res) {
  const userId = getUserId(req);

  if (!userId) {
    return error(
      res,
      401,
      "Требуется вход"
    );
  }

  const data = await body(req);

  const publicKey =
    String(data.publicKey || "")
      .toUpperCase();

  if (!isPublicKeyValid(publicKey)) {
    return error(
      res,
      400,
      "Некорректный public key"
    );
  }

  const address =
    deriveAddress(publicKey);

  const client =
    await pool.connect();

  try {
    await client.query("BEGIN");

    await client.query(
      "SELECT pg_advisory_xact_lock(1988019)"
    );

    const duplicate =
      await client.query(
        `
        SELECT id
        FROM wallets
        WHERE address=$1
        `,
        [address]
      );

    if (duplicate.rowCount) {
      await client.query("ROLLBACK");

      return error(
        res,
        409,
        "Такой криптографический кошелёк уже существует"
      );
    }

    const total =
      await getTotalSupply(client);

    if (
      total + Number(INITIAL_BALANCE) >
      Number(MAX_SUPPLY)
    ) {
      await client.query("ROLLBACK");

      return error(
        res,
        503,
        "Недостаточно доступной эмиссии"
      );
    }

    const result =
      await client.query(
        `
        INSERT INTO wallets(
          owner_id,
          address,
          balance,
          public_key,
          nonce
        )
        VALUES($1,$2,$3,$4,0)
        RETURNING *
        `,
        [
          userId,
          address,
          INITIAL_BALANCE,
          publicKey
        ]
      );

    await client.query("COMMIT");

    return json(res, 201, {
      ok: true,
      wallet: result.rows[0]
    });
  } catch (e) {
    try {
      await client.query("ROLLBACK");
    } catch {}

    console.error(e);

    return error(
      res,
      500,
      "Не удалось создать кошелёк"
    );
  } finally {
    client.release();
  }
}

async function wallets(req, res) {
  const userId = getUserId(req);

  if (!userId) {
    return error(res, 401, "Требуется вход");
  }

  return json(res, 200, {
    ok: true,
    wallets:
      await getWallets(userId)
  });
}

async function walletById(req, res, id) {
  const userId = getUserId(req);

  if (!userId) {
    return error(res, 401, "Требуется вход");
  }

  const result = await pool.query(
    `
    SELECT
      id,
      address,
      balance,
      public_key,
      nonce,
      created_at
    FROM wallets
    WHERE id=$1
      AND owner_id=$2
    `,
    [id, userId]
  );

  if (!result.rowCount) {
    return error(
      res,
      404,
      "Кошелёк не найден"
    );
  }

  return json(res, 200, {
    ok: true,
    wallet: result.rows[0]
  });
}

async function sendTransaction(req, res) {
  const userId = getUserId(req);

  if (!userId) {
    return error(res, 401, "Требуется вход");
  }

  const data = await body(req);

  const walletId =
    Number(data.walletId);

  const to =
    String(data.to || "")
      .toUpperCase();

  const amount =
    Number(data.amount);

  const publicKey =
    String(data.publicKey || "")
      .toUpperCase();

  const signature =
    String(data.signature || "")
      .toLowerCase();

  const nonce =
    Number(data.nonce);

  const timestamp =
    Number(data.timestamp);

  if (!Number.isInteger(walletId)) {
    return error(
      res,
      400,
      "Некорректный walletId"
    );
  }

  if (!isAddressValid(to)) {
    return error(
      res,
      400,
      "Некорректный адрес получателя"
    );
  }

  if (!isAmountValid(amount)) {
    return error(
      res,
      400,
      "Некорректная сумма"
    );
  }

  if (!isPublicKeyValid(publicKey)) {
    return error(
      res,
      400,
      "Некорректный public key"
    );
  }

  if (!isSignatureValid(signature)) {
    return error(
      res,
      400,
      "Некорректная подпись"
    );
  }

  if (!Number.isSafeInteger(nonce)) {
    return error(
      res,
      400,
      "Некорректный nonce"
    );
  }

  if (!Number.isSafeInteger(timestamp)) {
    return error(
      res,
      400,
      "Некорректное время"
    );
  }

  if (
    Math.abs(Date.now() - timestamp) >
    5 * 60 * 1000
  ) {
    return error(
      res,
      400,
      "Время транзакции устарело"
    );
  }

  const derivedAddress =
    deriveAddress(publicKey);

  const client =
    await pool.connect();

  try {
    await client.query("BEGIN");

    const senderResult =
      await client.query(
        `
        SELECT *
        FROM wallets
        WHERE id=$1
          AND owner_id=$2
        FOR UPDATE
        `,
        [walletId, userId]
      );

    if (!senderResult.rowCount) {
      await client.query("ROLLBACK");

      return error(
        res,
        404,
        "Кошелёк отправителя не найден"
      );
    }

    const sender =
      senderResult.rows[0];

    if (!sender.public_key) {
      await client.query("ROLLBACK");

      return error(
        res,
        400,
        "Этот кошелёк не поддерживает v1.9. Создайте новый криптографический кошелёк."
      );
    }

    if (
      sender.public_key.toUpperCase() !==
      publicKey
    ) {
      await client.query("ROLLBACK");

      return error(
        res,
        400,
        "Public key не принадлежит этому кошельку"
      );
    }

    if (
      sender.address !==
      derivedAddress
    ) {
      await client.query("ROLLBACK");

      return error(
        res,
        400,
        "Адрес не соответствует public key"
      );
    }

    if (
      Number(sender.nonce) !== nonce
    ) {
      await client.query("ROLLBACK");

      return error(
        res,
        409,
        `Неверный nonce. Ожидается ${sender.nonce}`
      );
    }

    if (sender.address === to) {
      await client.query("ROLLBACK");

      return error(
        res,
        400,
        "Нельзя отправлять самому себе"
      );
    }

    const fee =
      Number(TRANSFER_FEE);

    const total =
      amount + fee;

    if (
      Number(sender.balance) <
      total
    ) {
      await client.query("ROLLBACK");

      return error(
        res,
        400,
        "Недостаточно SLX"
      );
    }

    const recipientResult =
      await client.query(
        `
        SELECT *
        FROM wallets
        WHERE address=$1
        FOR UPDATE
        `,
        [to]
      );

    if (!recipientResult.rowCount) {
      await client.query("ROLLBACK");

      return error(
        res,
        404,
        "Кошелёк получателя не найден"
      );
    }

    const tx = {
      from: sender.address,
      to,
      amount,
      fee,
      nonce,
      timestamp
    };

    const message =
      canonicalTransaction(tx);

    const valid =
      await verifyEd25519(
        publicKey,
        signature,
        message
      );

    if (!valid) {
      await client.query("ROLLBACK");

      return error(
        res,
        401,
        "Неверная криптографическая подпись"
      );
    }

    const recipient =
      recipientResult.rows[0];

    await client.query(
      `
      UPDATE wallets
      SET
        balance = balance - $1,
        nonce = nonce + 1
      WHERE id=$2
      `,
      [
        total,
        sender.id
      ]
    );

    await client.query(
      `
      UPDATE wallets
      SET balance = balance + $1
      WHERE id=$2
      `,
      [
        amount,
        recipient.id
      ]
    );

    const senderTx =
      await client.query(
        `
        INSERT INTO transactions(
          wallet_id,
          type,
          amount,
          from_wallet,
          to_wallet,
          fee,
          nonce,
          public_key,
          signature
        )
        VALUES(
          $1,
          'SEND',
          $2,
          $3,
          $4,
          $5,
          $6,
          $7,
          $8
        )
        RETURNING id
        `,
        [
          sender.id,
          amount,
          sender.address,
          to,
          fee,
          nonce,
          publicKey,
          signature
        ]
      );

    const receiverTx =
      await client.query(
        `
        INSERT INTO transactions(
          wallet_id,
          type,
          amount,
          from_wallet,
          to_wallet,
          fee,
          nonce,
          public_key,
          signature
        )
        VALUES(
          $1,
          'RECEIVE',
          $2,
          $3,
          $4,
          0,
          $5,
          $6,
          $7
        )
        RETURNING id
        `,
        [
          recipient.id,
          amount,
          sender.address,
          to,
          nonce,
          publicKey,
          signature
        ]
      );

    const root =
      merkleRoot([
        message,
        signature,
        publicKey,
        String(senderTx.rows[0].id),
        String(receiverTx.rows[0].id)
      ]);

    const block =
      await createBlock(
        client,
        sender.address,
        2,
        root
      );

    await client.query("COMMIT");

    return json(res, 200, {
      ok: true,
      message:
        "Транзакция успешно подписана и подтверждена",
      transaction: {
        from: sender.address,
        to,
        amount,
        fee,
        nonce,
        signature,
        publicKey,
        timestamp
      },
      block
    });
  } catch (e) {
    try {
      await client.query("ROLLBACK");
    } catch {}

    console.error(e);

    return error(
      res,
      500,
      "Ошибка выполнения транзакции"
    );
  } finally {
    client.release();
  }
}

async function faucet(req, res) {
  const userId = getUserId(req);

  if (!userId) {
    return error(res, 401, "Требуется вход");
  }

  const data = await body(req);

  const walletId =
    Number(data.walletId);

  const client =
    await pool.connect();

  try {
    await client.query("BEGIN");

    await client.query(
      "SELECT pg_advisory_xact_lock(771919)"
    );

    const walletResult =
      await client.query(
        `
        SELECT *
        FROM wallets
        WHERE id=$1
          AND owner_id=$2
        FOR UPDATE
        `,
        [walletId, userId]
      );

    if (!walletResult.rowCount) {
      await client.query("ROLLBACK");

      return error(
        res,
        404,
        "Кошелёк не найден"
      );
    }

    const wallet =
      walletResult.rows[0];

    const claim =
      await client.query(
        `
        SELECT last_claim_at
        FROM faucet_claims
        WHERE wallet_id=$1
        `,
        [walletId]
      );

    if (claim.rowCount) {
      const last =
        new Date(
          claim.rows[0].last_claim_at
        ).getTime();

      const remaining =
        FAUCET_COOLDOWN_MS -
        (Date.now() - last);

      if (remaining > 0) {
        await client.query("ROLLBACK");

        const hours =
          Math.ceil(
            remaining / 3600000
          );

        return error(
          res,
          429,
          `Faucet будет доступен примерно через ${hours} ч.`
        );
      }
    }

    const total =
      await getTotalSupply(client);

    if (
      total + Number(FAUCET_AMOUNT) >
      Number(MAX_SUPPLY)
    ) {
      await client.query("ROLLBACK");

      return error(
        res,
        503,
        "Достигнут MAX_SUPPLY"
      );
    }

    await client.query(
      `
      UPDATE wallets
      SET balance=balance+$1
      WHERE id=$2
      `,
      [
        FAUCET_AMOUNT,
        walletId
      ]
    );

    await client.query(
      `
      INSERT INTO faucet_claims(
        wallet_id,
        last_claim_at
      )
      VALUES($1,NOW())
      ON CONFLICT(wallet_id)
      DO UPDATE SET
        last_claim_at=EXCLUDED.last_claim_at
      `,
      [walletId]
    );

    const tx =
      await client.query(
        `
        INSERT INTO transactions(
          wallet_id,
          type,
          amount,
          from_wallet,
          to_wallet,
          fee,
          nonce
        )
        VALUES(
          $1,
          'FAUCET',
          $2,
          'FAUCET',
          $3,
          0,
          NULL
        )
        RETURNING id
        `,
        [
          walletId,
          FAUCET_AMOUNT,
          wallet.address
        ]
      );

    const root =
      merkleRoot([
        `FAUCET:${tx.rows[0].id}`,
        wallet.address,
        String(FAUCET_AMOUNT)
      ]);

    const block =
      await createBlock(
        client,
        "FAUCET",
        1,
        root
      );

    await client.query("COMMIT");

    return json(res, 200, {
      ok: true,
      amount: Number(FAUCET_AMOUNT),
      block
    });
  } catch (e) {
    try {
      await client.query("ROLLBACK");
    } catch {}

    console.error(e);

    return error(
      res,
      500,
      "Ошибка faucet"
    );
  } finally {
    client.release();
  }
}

async function history(req, res) {
  const userId = getUserId(req);

  if (!userId) {
    return error(res, 401, "Требуется вход");
  }

  const result =
    await pool.query(
      `
      SELECT
        t.*,
        w.address
      FROM transactions t
      JOIN wallets w
        ON w.id=t.wallet_id
      WHERE w.owner_id=$1
      ORDER BY t.id DESC
      LIMIT 100
      `,
      [userId]
    );

  return json(res, 200, {
    ok: true,
    transactions:
      result.rows
  });
}

async function status(req, res) {
  const blocks =
    await pool.query(`
      SELECT COUNT(*)::integer AS count
      FROM blocks
    `);

  const wallets =
    await pool.query(`
      SELECT COUNT(*)::integer AS count
      FROM wallets
    `);

  const transactions =
    await pool.query(`
      SELECT COUNT(*)::integer AS count
      FROM transactions
    `);

  const supply =
    await getTotalSupply();

  return json(res, 200, {
    ok: true,
    network: NETWORK_VERSION,
    networkId: NETWORK_ID,
    status: "online",
    cryptography: "Ed25519",
    blocks: blocks.rows[0].count,
    wallets: wallets.rows[0].count,
    transactions:
      transactions.rows[0].count,
    circulatingSupply: supply,
    maxSupply: Number(MAX_SUPPLY),
    fee: Number(TRANSFER_FEE),
    faucet: Number(FAUCET_AMOUNT)
  });
}

async function economy(req, res) {
  const supply =
    await getTotalSupply();

  return json(res, 200, {
    ok: true,
    maxSupply: Number(MAX_SUPPLY),
    circulatingSupply: supply,
    remaining:
      Math.max(
        0,
        Number(MAX_SUPPLY) - supply
      ),
    fee: Number(TRANSFER_FEE),
    faucet: Number(FAUCET_AMOUNT),
    network: NETWORK_VERSION
  });
}

async function blocks(req, res) {
  const result =
    await pool.query(`
      SELECT *
      FROM blocks
      ORDER BY block_index DESC
      LIMIT 50
    `);

  return json(res, 200, {
    ok: true,
    blocks: result.rows
  });
}

async function verifyChain(req, res) {
  const result =
    await pool.query(`
      SELECT *
      FROM blocks
      ORDER BY block_index ASC
    `);

  const chain =
    result.rows;

  if (!chain.length) {
    return json(res, 200, {
      ok: true,
      valid: true,
      blocks: 0
    });
  }

  for (let i = 0; i < chain.length; i++) {
    const block = chain[i];

    if (
      Number(block.block_index) !== i
    ) {
      return json(res, 200, {
        ok: true,
        valid: false,
        reason:
          `Нарушен block_index на ${i}`
      });
    }

    if (i === 0) {
      if (
        block.previous_hash !==
        "0".repeat(64)
      ) {
        return json(res, 200, {
          ok: true,
          valid: false,
          reason:
            "Некорректный genesis block"
        });
      }

      continue;
    }

    const previous =
      chain[i - 1];

    if (
      block.previous_hash !==
      previous.hash
    ) {
      return json(res, 200, {
        ok: true,
        valid: false,
        reason:
          `Разрыв цепочки перед блоком ${i}`
      });
    }
  }

  return json(res, 200, {
    ok: true,
    valid: true,
    blocks: chain.length,
    message:
      "Blockchain structure verified"
  });
}

async function changePassword(req, res) {
  const userId = getUserId(req);

  if (!userId) {
    return error(res, 401, "Требуется вход");
  }

  const data = await body(req);

  const oldPassword =
    data.oldPassword;

  const newPassword =
    data.newPassword;

  if (
    !isPasswordValid(newPassword)
  ) {
    return error(
      res,
      400,
      "Новый пароль должен содержать минимум 8 символов"
    );
  }

  const result =
    await pool.query(
      `
      SELECT password_hash
      FROM users
      WHERE id=$1
      `,
      [userId]
    );

  if (
    !result.rowCount ||
    !verifyPassword(
      oldPassword,
      result.rows[0].password_hash
    )
  ) {
    return error(
      res,
      401,
      "Старый пароль неверный"
    );
  }

  await pool.query(
    `
    UPDATE users
    SET password_hash=$1
    WHERE id=$2
    `,
    [
      hashPassword(newPassword),
      userId
    ]
  );

  for (const [token, session] of sessions) {
    if (session.userId === userId) {
      sessions.delete(token);
    }
  }

  const token =
    createSession(userId);

  return json(res, 200, {
    ok: true,
    token
  });
}

async function recoveryReset(req, res) {
  const data = await body(req);

  const username =
    normalizeUsername(data.username);

  const recoveryCode =
    String(data.recoveryCode || "")
      .trim()
      .toUpperCase();

  const newPassword =
    data.newPassword;

  if (!isPasswordValid(newPassword)) {
    return error(
      res,
      400,
      "Новый пароль должен содержать минимум 8 символов"
    );
  }

  const result =
    await pool.query(
      `
      SELECT id, recovery_code_hash
      FROM users
      WHERE username=$1
      `,
      [username]
    );

  if (!result.rowCount) {
    return error(
      res,
      401,
      "Неверные данные восстановления"
    );
  }

  const user =
    result.rows[0];

  if (
    hashRecovery(recoveryCode) !==
    user.recovery_code_hash
  ) {
    return error(
      res,
      401,
      "Неверный recovery code"
    );
  }

  await pool.query(
    `
    UPDATE users
    SET password_hash=$1
    WHERE id=$2
    `,
    [
      hashPassword(newPassword),
      user.id
    ]
  );

  for (const [token, session] of sessions) {
    if (session.userId === user.id) {
      sessions.delete(token);
    }
  }

  const token =
    createSession(user.id);

  return json(res, 200, {
    ok: true,
    token
  });
}

async function route(req, res) {
  const url =
    new URL(
      req.url,
      `http://${req.headers.host}`
    );

  const pathname =
    url.pathname;

  try {
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
      pathname === "/api/auth/password/change"
    ) {
      return await changePassword(
        req,
        res
      );
    }

    if (
      req.method === "POST" &&
      pathname === "/api/auth/recovery/reset"
    ) {
      return await recoveryReset(
        req,
        res
      );
    }

    if (
      req.method === "POST" &&
      pathname === "/api/auth/logout"
    ) {
      const token = getToken(req);

      if (token) {
        sessions.delete(token);
      }

      return json(res, 200, {
        ok: true
      });
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
      return await createWallet(
        req,
        res
      );
    }

    if (
      req.method === "GET" &&
      pathname.startsWith("/api/wallet/")
    ) {
      const id =
        pathname.split("/").pop();

      return await walletById(
        req,
        res,
        id
      );
    }

    if (
      req.method === "POST" &&
      pathname === "/api/send"
    ) {
      return await sendTransaction(
        req,
        res
      );
    }

    if (
      req.method === "POST" &&
      pathname === "/api/faucet"
    ) {
      return await faucet(req, res);
    }

    if (
      req.method === "GET" &&
      pathname === "/api/history"
    ) {
      return await history(req, res);
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
      return await verifyChain(
        req,
        res
      );
    }

    if (
      req.method === "GET" &&
      pathname === "/api/health"
    ) {
      return json(res, 200, {
        ok: true,
        version: NETWORK_VERSION
      });
    }

    // Frontend
    let filePath = pathname;

    if (
      filePath === "/" ||
      filePath === ""
    ) {
      filePath = "/index.html";
    }

    const fullPath =
      path.join(
        PUBLIC_DIR,
        filePath
      );

    if (
      !fullPath.startsWith(
        PUBLIC_DIR
      )
    ) {
      return error(res, 403, "Forbidden");
    }

    if (!fs.existsSync(fullPath)) {
      return error(res, 404, "Not found");
    }

    const ext =
      path.extname(fullPath)
        .toLowerCase();

    const types = {
      ".html": "text/html; charset=utf-8",
      ".css": "text/css; charset=utf-8",
      ".js": "text/javascript; charset=utf-8",
      ".json": "application/json; charset=utf-8",
      ".png": "image/png",
      ".jpg": "image/jpeg",
      ".svg": "image/svg+xml"
    };

    res.writeHead(200, {
      "Content-Type":
        types[ext] ||
        "application/octet-stream"
    });

    fs.createReadStream(
      fullPath
    ).pipe(res);

  } catch (e) {
    console.error(e);

    if (!res.headersSent) {
      error(
        res,
        e.message === "BODY_TOO_LARGE"
          ? 413
          : 500,
        e.message === "BODY_TOO_LARGE"
          ? "Request too large"
          : "Server error"
      );
    }
  }
}

initDB()
  .then(() => {
    const server =
      http.createServer(route);

    server.listen(
      PORT,
      "0.0.0.0",
      () => {
        console.log(
          `SLX Network v${NETWORK_VERSION} running on port ${PORT}`
        );

        console.log(
          `Network: ${NETWORK_ID}`
        );

        console.log(
          "Cryptography: Ed25519"
        );
      }
    );
  })
  .catch(err => {
    console.error(
      "Database initialization failed:",
      err
    );

    process.exit(1);
  });