const http = require("http");
const crypto = require("crypto");
const { Pool } = require("pg");

const PORT = process.env.PORT || 10000;

if (!process.env.DATABASE_URL) {
    console.error("DATABASE_URL is not set");
    process.exit(1);
}

/* =========================
   POSTGRESQL
========================= */

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});


/* =========================
   SESSIONS
========================= */

const sessions = new Map();


/* =========================
   HELPERS
========================= */

function makeId() {
    return (
        "SLX" +
        crypto
            .randomBytes(5)
            .toString("hex")
            .toUpperCase()
    );
}

function makeAddress() {
    return (
        "SLX-" +
        crypto
            .randomBytes(8)
            .toString("hex")
            .toUpperCase()
    );
}

function makeUserId() {
    return (
        "USR" +
        crypto
            .randomBytes(8)
            .toString("hex")
            .toUpperCase()
    );
}

function makeSessionToken() {
    return crypto
        .randomBytes(32)
        .toString("hex");
}

function makeTransactionId() {
    return (
        "TX" +
        crypto
            .randomBytes(12)
            .toString("hex")
            .toUpperCase()
    );
}

function hashPassword(password) {
    return crypto
        .createHash("sha256")
        .update(password)
        .digest("hex");
}

function sendJSON(res, status, data) {

    res.writeHead(
        status,
        {
            "Content-Type":
                "application/json; charset=utf-8",

            "Access-Control-Allow-Origin":
                "*",

            "Access-Control-Allow-Headers":
                "Content-Type, Authorization",

            "Access-Control-Allow-Methods":
                "GET, POST, OPTIONS"
        }
    );

    res.end(
        JSON.stringify(data)
    );
}

function sendHTML(res, html) {

    res.writeHead(
        200,
        {
            "Content-Type":
                "text/html; charset=utf-8",

            "Access-Control-Allow-Origin":
                "*"
        }
    );

    res.end(html);
}

function getBody(req) {

    return new Promise(
        (resolve, reject) => {

            let body = "";

            req.on(
                "data",
                chunk => {
                    body += chunk.toString();
                }
            );

            req.on(
                "end",
                () => {

                    if (!body) {
                        resolve({});
                        return;
                    }

                    try {
                        resolve(
                            JSON.parse(body)
                        );
                    } catch {
                        reject(
                            new Error(
                                "Invalid JSON"
                            )
                        );
                    }
                }
            );

            req.on(
                "error",
                reject
            );
        }
    );
}


/* =========================
   DATABASE INIT
========================= */

async function initDatabase() {

    await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS wallets (
            id TEXT PRIMARY KEY,
            owner_id TEXT NOT NULL
                REFERENCES users(id)
                ON DELETE CASCADE,

            address TEXT UNIQUE NOT NULL,

            balance NUMERIC(30,8)
                NOT NULL DEFAULT 1000,

            created_at TIMESTAMPTZ
                NOT NULL DEFAULT NOW()
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS transactions (
            id TEXT PRIMARY KEY,

            wallet_id TEXT NOT NULL
                REFERENCES wallets(id)
                ON DELETE CASCADE,

            type TEXT NOT NULL,

            amount NUMERIC(30,8)
                NOT NULL,

            from_wallet TEXT,

            to_wallet TEXT,

            created_at TIMESTAMPTZ
                NOT NULL DEFAULT NOW()
        )
    `);

    await pool.query(`
        CREATE INDEX IF NOT EXISTS
        idx_wallets_owner
        ON wallets(owner_id)
    `);

    await pool.query(`
        CREATE INDEX IF NOT EXISTS
        idx_transactions_wallet
        ON transactions(wallet_id)
    `);

    console.log(
        "PostgreSQL database ready"
    );
}


/* =========================
   AUTH
========================= */

function getToken(req) {

    const auth =
        req.headers.authorization || "";

    if (
        !auth.startsWith(
            "Bearer "
        )
    ) {
        return null;
    }

    return auth.substring(7);
}

async function getCurrentUser(req) {

    const token =
        getToken(req);

    if (!token) {
        return null;
    }

    const userId =
        sessions.get(token);

    if (!userId) {
        return null;
    }

    const result =
        await pool.query(
            `
            SELECT
                id,
                username,
                created_at
            FROM users
            WHERE id = $1
            `,
            [userId]
        );

    if (!result.rows.length) {
        return null;
    }

    return result.rows[0];
}


/* =========================
   USER DATA
========================= */

async function getUserWallets(
    userId
) {

    const result =
        await pool.query(
            `
            SELECT
                id,
                address,
                balance,
                created_at
            FROM wallets
            WHERE owner_id = $1
            ORDER BY created_at ASC
            `,
            [userId]
        );

    return result.rows.map(
        wallet => ({
            id: wallet.id,
            address: wallet.address,
            balance:
                Number(wallet.balance),
            createdAt:
                wallet.created_at
        })
    );
}

async function getUserResponse(
    user
) {

    const wallets =
        await getUserWallets(
            user.id
        );

    return {
        id: user.id,

        username:
            user.username,

        createdAt:
            user.created_at,

        walletIds:
            wallets.map(
                wallet => wallet.id
            ),

        walletId:
            wallets.length
                ? wallets[0].id
                : null
    };
}


/* =========================
   WALLET DETAILS
========================= */

async function getWalletDetails(
    walletId
) {

    const walletResult =
        await pool.query(
            `
            SELECT
                id,
                owner_id,
                address,
                balance,
                created_at
            FROM wallets
            WHERE id = $1
            `,
            [walletId]
        );

    if (!walletResult.rows.length) {
        return null;
    }

    const wallet =
        walletResult.rows[0];

    const txResult =
        await pool.query(
            `
            SELECT
                id,
                type,
                amount,
                from_wallet,
                to_wallet,
                created_at
            FROM transactions
            WHERE wallet_id = $1
            ORDER BY created_at DESC
            `,
            [walletId]
        );

    return {
        id: wallet.id,

        address:
            wallet.address,

        balance:
            Number(wallet.balance),

        createdAt:
            wallet.created_at,

        transactions:
            txResult.rows.map(
                tx => ({
                    id: tx.id,

                    type: tx.type,

                    amount:
                        Number(tx.amount),

                    from:
                        tx.from_wallet,

                    to:
                        tx.to_wallet,

                    time:
                        tx.created_at
                })
            )
    };
}


/* =========================
   SERVER
========================= */

const server =
    http.createServer(
        async (req, res) => {

            try {

                /* OPTIONS */

                if (
                    req.method ===
                    "OPTIONS"
                ) {

                    res.writeHead(
                        204,
                        {
                            "Access-Control-Allow-Origin":
                                "*",

                            "Access-Control-Allow-Headers":
                                "Content-Type, Authorization",

                            "Access-Control-Allow-Methods":
                                "GET, POST, OPTIONS"
                        }
                    );

                    res.end();

                    return;
                }


                const url =
                    new URL(
                        req.url,
                        `http://${req.headers.host}`
                    );

                const pathname =
                    url.pathname;


                /* =========================
                   HOME
                ========================= */

                if (
                    req.method === "GET" &&
                    pathname === "/"
                ) {

                    const fs =
                        require("fs");

                    const path =
                        require("path");

                    const file =
                        path.join(
                            __dirname,
                            "index.html"
                        );

                    if (
                        fs.existsSync(file)
                    ) {

                        sendHTML(
                            res,
                            fs.readFileSync(
                                file,
                                "utf8"
                            )
                        );

                    } else {

                        sendJSON(
                            res,
                            404,
                            {
                                success: false,
                                error:
                                    "index.html not found"
                            }
                        );
                    }

                    return;
                }


                /* =========================
                   STATUS
                ========================= */

                if (
                    req.method === "GET" &&
                    pathname === "/api/status"
                ) {

                    const users =
                        await pool.query(
                            "SELECT COUNT(*) FROM users"
                        );

                    const wallets =
                        await pool.query(
                            "SELECT COUNT(*) FROM wallets"
                        );

                    sendJSON(
                        res,
                        200,
                        {
                            success: true,

                            network:
                                "SLX Testnet",

                            version:
                                "1.5",

                            accounts:
                                Number(
                                    users.rows[0].count
                                ),

                            wallets:
                                Number(
                                    wallets.rows[0].count
                                )
                        }
                    );

                    return;
                }


                /* =========================
                   REGISTER
                ========================= */

                if (
                    req.method === "POST" &&
                    pathname ===
                    "/api/auth/register"
                ) {

                    const body =
                        await getBody(req);

                    const username =
                        String(
                            body.username || ""
                        ).trim();

                    const password =
                        String(
                            body.password || ""
                        );

                    if (
                        username.length < 3
                    ) {

                        sendJSON(
                            res,
                            400,
                            {
                                success: false,
                                error:
                                    "Имя пользователя должно быть не менее 3 символов."
                            }
                        );

                        return;
                    }

                    if (
                        password.length < 4
                    ) {

                        sendJSON(
                            res,
                            400,
                            {
                                success: false,
                                error:
                                    "Пароль должен быть не менее 4 символов."
                            }
                        );

                        return;
                    }

                    const existing =
                        await pool.query(
                            `
                            SELECT id
                            FROM users
                            WHERE LOWER(username)
                                = LOWER($1)
                            `,
                            [username]
                        );

                    if (
                        existing.rows.length
                    ) {

                        sendJSON(
                            res,
                            409,
                            {
                                success: false,
                                error:
                                    "Такой пользователь уже существует."
                            }
                        );

                        return;
                    }

                    const userId =
                        makeUserId();

                    const walletId =
                        makeId();

                    const address =
                        makeAddress();

                    const passwordHash =
                        hashPassword(
                            password
                        );

                    const client =
                        await pool.connect();

                    try {

                        await client.query(
                            "BEGIN"
                        );

                        await client.query(
                            `
                            INSERT INTO users
                            (
                                id,
                                username,
                                password_hash
                            )
                            VALUES
                            ($1,$2,$3)
                            `,
                            [
                                userId,
                                username,
                                passwordHash
                            ]
                        );

                        await client.query(
                            `
                            INSERT INTO wallets
                            (
                                id,
                                owner_id,
                                address,
                                balance
                            )
                            VALUES
                            ($1,$2,$3,1000)
                            `,
                            [
                                walletId,
                                userId,
                                address
                            ]
                        );

                        await client.query(
                            "COMMIT"
                        );

                    } catch (error) {

                        await client.query(
                            "ROLLBACK"
                        );

                        throw error;

                    } finally {

                        client.release();
                    }

                    const token =
                        makeSessionToken();

                    sessions.set(
                        token,
                        userId
                    );

                    sendJSON(
                        res,
                        201,
                        {
                            success: true,

                            token,

                            user: {
                                id: userId,

                                username,

                                walletId,

                                walletIds: [
                                    walletId
                                ]
                            }
                        }
                    );

                    return;
                }


                /* =========================
                   LOGIN
                ========================= */

                if (
                    req.method === "POST" &&
                    pathname ===
                    "/api/auth/login"
                ) {

                    const body =
                        await getBody(req);

                    const username =
                        String(
                            body.username || ""
                        ).trim();

                    const password =
                        String(
                            body.password || ""
                        );

                    const result =
                        await pool.query(
                            `
                            SELECT *
                            FROM users
                            WHERE LOWER(username)
                                = LOWER($1)
                            `,
                            [username]
                        );

                    if (
                        !result.rows.length
                    ) {

                        sendJSON(
                            res,
                            401,
                            {
                                success: false,
                                error:
                                    "Неверное имя пользователя или пароль."
                            }
                        );

                        return;
                    }

                    const user =
                        result.rows[0];

                    const passwordHash =
                        hashPassword(
                            password
                        );

                    if (
                        passwordHash !==
                        user.password_hash
                    ) {

                        sendJSON(
                            res,
                            401,
                            {
                                success: false,
                                error:
                                    "Неверное имя пользователя или пароль."
                            }
                        );

                        return;
                    }

                    const token =
                        makeSessionToken();

                    sessions.set(
                        token,
                        user.id
                    );

                    const userData =
                        await getUserResponse(
                            user
                        );

                    sendJSON(
                        res,
                        200,
                        {
                            success: true,

                            token,

                            user:
                                userData
                        }
                    );

                    return;
                }


                /* =========================
                   ME
                ========================= */

                if (
                    req.method === "GET" &&
                    pathname ===
                    "/api/auth/me"
                ) {

                    const user =
                        await getCurrentUser(
                            req
                        );

                    if (!user) {

                        sendJSON(
                            res,
                            401,
                            {
                                success: false,
                                error:
                                    "Не авторизован."
                            }
                        );

                        return;
                    }

                    sendJSON(
                        res,
                        200,
                        {
                            success: true,

                            user:
                                await getUserResponse(
                                    user
                                )
                        }
                    );

                    return;
                }


                /* =========================
                   LOGOUT
                ========================= */

                if (
                    req.method === "POST" &&
                    pathname ===
                    "/api/auth/logout"
                ) {

                    const token =
                        getToken(req);

                    if (token) {
                        sessions.delete(
                            token
                        );
                    }

                    sendJSON(
                        res,
                        200,
                        {
                            success: true
                        }
                    );

                    return;
                }


                /* =========================
                   AUTH CHECK
                ========================= */

                const user =
                    await getCurrentUser(
                        req
                    );

                if (!user) {

                    sendJSON(
                        res,
                        401,
                        {
                            success: false,
                            error:
                                "Требуется авторизация."
                        }
                    );

                    return;
                }


                /* =========================
                   MY WALLETS
                ========================= */

                if (
                    req.method === "GET" &&
                    pathname ===
                    "/api/wallets"
                ) {

                    const wallets =
                        await getUserWallets(
                            user.id
                        );

                    sendJSON(
                        res,
                        200,
                        {
                            success: true,
                            wallets
                        }
                    );

                    return;
                }


                /* =========================
                   CREATE WALLET
                ========================= */

                if (
                    req.method === "POST" &&
                    pathname ===
                    "/api/wallet/create"
                ) {

                    const walletId =
                        makeId();

                    const address =
                        makeAddress();

                    await pool.query(
                        `
                        INSERT INTO wallets
                        (
                            id,
                            owner_id,
                            address,
                            balance
                        )
                        VALUES
                        ($1,$2,$3,1000)
                        `,
                        [
                            walletId,
                            user.id,
                            address
                        ]
                    );

                    const wallet =
                        await getWalletDetails(
                            walletId
                        );

                    const wallets =
                        await getUserWallets(
                            user.id
                        );

                    sendJSON(
                        res,
                        201,
                        {
                            success: true,

                            wallet,

                            walletIds:
                                wallets.map(
                                    w => w.id
                                )
                        }
                    );

                    return;
                }


                /* =========================
                   SELECT WALLET
                ========================= */

                if (
                    req.method === "POST" &&
                    pathname ===
                    "/api/wallet/select"
                ) {

                    const body =
                        await getBody(req);

                    const walletId =
                        String(
                            body.id || ""
                        );

                    const result =
                        await pool.query(
                            `
                            SELECT id
                            FROM wallets
                            WHERE id = $1
                            AND owner_id = $2
                            `,
                            [
                                walletId,
                                user.id
                            ]
                        );

                    if (
                        !result.rows.length
                    ) {

                        sendJSON(
                            res,
                            404,
                            {
                                success: false,
                                error:
                                    "Кошелёк не принадлежит этому аккаунту."
                            }
                        );

                        return;
                    }

                    const wallet =
                        await getWalletDetails(
                            walletId
                        );

                    sendJSON(
                        res,
                        200,
                        {
                            success: true,
                            wallet
                        }
                    );

                    return;
                }


                /* =========================
                   WALLET BY ID
                ========================= */

                const walletMatch =
                    pathname.match(
                        /^\/api\/wallet\/([^/]+)$/
                    );

                if (
                    req.method === "GET" &&
                    walletMatch
                ) {

                    const walletId =
                        decodeURIComponent(
                            walletMatch[1]
                        );

                    const ownership =
                        await pool.query(
                            `
                            SELECT id
                            FROM wallets
                            WHERE id = $1
                            AND owner_id = $2
                            `,
                            [
                                walletId,
                                user.id
                            ]
                        );

                    if (
                        !ownership.rows.length
                    ) {

                        sendJSON(
                            res,
                            403,
                            {
                                success: false,
                                error:
                                    "Нет доступа к этому кошельку."
                            }
                        );

                        return;
                    }

                    const wallet =
                        await getWalletDetails(
                            walletId
                        );

                    sendJSON(
                        res,
                        200,
                        {
                            success: true,
                            wallet
                        }
                    );

                    return;
                }


                /* =========================
                   FIND WALLET
                ========================= */

                const findMatch =
                    pathname.match(
                        /^\/api\/find\/([^/]+)$/
                    );

                if (
                    req.method === "GET" &&
                    findMatch
                ) {

                    const walletId =
                        decodeURIComponent(
                            findMatch[1]
                        );

                    const result =
                        await pool.query(
                            `
                            SELECT
                                id,
                                address,
                                balance
                            FROM wallets
                            WHERE id = $1
                            `,
                            [walletId]
                        );

                    if (
                        !result.rows.length
                    ) {

                        sendJSON(
                            res,
                            404,
                            {
                                success: false,
                                error:
                                    "Кошелёк не найден."
                            }
                        );

                        return;
                    }

                    const wallet =
                        result.rows[0];

                    sendJSON(
                        res,
                        200,
                        {
                            success: true,

                            wallet: {
                                id:
                                    wallet.id,

                                address:
                                    wallet.address,

                                balance:
                                    Number(
                                        wallet.balance
                                    )
                            }
                        }
                    );

                    return;
                }


                /* =========================
                   FAUCET
                ========================= */

                if (
                    req.method === "POST" &&
                    pathname ===
                    "/api/faucet"
                ) {

                    const body =
                        await getBody(req);

                    const walletId =
                        String(
                            body.id || ""
                        );

                    const ownership =
                        await pool.query(
                            `
                            SELECT id
                            FROM wallets
                            WHERE id = $1
                            AND owner_id = $2
                            `,
                            [
                                walletId,
                                user.id
                            ]
                        );

                    if (
                        !ownership.rows.length
                    ) {

                        sendJSON(
                            res,
                            403,
                            {
                                success: false,
                                error:
                                    "Нет доступа к этому кошельку."
                            }
                        );

                        return;
                    }

                    const client =
                        await pool.connect();

                    try {

                        await client.query(
                            "BEGIN"
                        );

                        await client.query(
                            `
                            UPDATE wallets
                            SET balance =
                                balance + 100
                            WHERE id = $1
                            `,
                            [walletId]
                        );

                        await client.query(
                            `
                            INSERT INTO transactions
                            (
                                id,
                                wallet_id,
                                type,
                                amount,
                                from_wallet,
                                to_wallet
                            )
                            VALUES
                            ($1,$2,'faucet',100,NULL,$2)
                            `,
                            [
                                makeTransactionId(),
                                walletId
                            ]
                        );

                        await client.query(
                            "COMMIT"
                        );

                    } catch (error) {

                        await client.query(
                            "ROLLBACK"
                        );

                        throw error;

                    } finally {

                        client.release();
                    }

                    const wallet =
                        await getWalletDetails(
                            walletId
                        );

                    sendJSON(
                        res,
                        200,
                        {
                            success: true,
                            wallet
                        }
                    );

                    return;
                }


                /* =========================
                   SEND SLX
                ========================= */

                if (
                    req.method === "POST" &&
                    pathname ===
                    "/api/send"
                ) {

                    const body =
                        await getBody(req);

                    const sender =
                        String(
                            body.sender || ""
                        );

                    const recipient =
                        String(
                            body.recipient || ""
                        );

                    const amount =
                        Number(
                            body.amount
                        );

                    if (
                        !sender ||
                        !recipient
                    ) {

                        sendJSON(
                            res,
                            400,
                            {
                                success: false,
                                error:
                                    "Не указан отправитель или получатель."
                            }
                        );

                        return;
                    }

                    if (
                        sender ===
                        recipient
                    ) {

                        sendJSON(
                            res,
                            400,
                            {
                                success: false,
                                error:
                                    "Нельзя отправить SLX самому себе."
                            }
                        );

                        return;
                    }

                    if (
                        !Number.isFinite(
                            amount
                        ) ||
                        amount <= 0
                    ) {

                        sendJSON(
                            res,
                            400,
                            {
                                success: false,
                                error:
                                    "Неверная сумма."
                            }
                        );

                        return;
                    }

                    const client =
                        await pool.connect();

                    try {

                        await client.query(
                            "BEGIN"
                        );

                        const senderResult =
                            await client.query(
                                `
                                SELECT
                                    id,
                                    owner_id,
                                    balance
                                FROM wallets
                                WHERE id = $1
                                FOR UPDATE
                                `,
                                [sender]
                            );

                        const recipientResult =
                            await client.query(
                                `
                                SELECT
                                    id,
                                    balance
                                FROM wallets
                                WHERE id = $1
                                FOR UPDATE
                                `,
                                [recipient]
                            );

                        if (
                            !senderResult.rows.length
                        ) {

                            throw new Error(
                                "Кошелёк отправителя не найден."
                            );
                        }

                        if (
                            !recipientResult.rows.length
                        ) {

                            throw new Error(
                                "Кошелёк получателя не найден."
                            );
                        }

                        const senderWallet =
                            senderResult.rows[0];

                        const recipientWallet =
                            recipientResult.rows[0];

                        if (
                            senderWallet.owner_id !==
                            user.id
                        ) {

                            throw new Error(
                                "Этот кошелёк не принадлежит вашему аккаунту."
                            );
                        }

                        const senderBalance =
                            Number(
                                senderWallet.balance
                            );

                        if (
                            senderBalance <
                            amount
                        ) {

                            throw new Error(
                                "Недостаточно SLX."
                            );
                        }

                        await client.query(
                            `
                            UPDATE wallets
                            SET balance =
                                balance - $1
                            WHERE id = $2
                            `,
                            [
                                amount,
                                sender
                            ]
                        );

                        await client.query(
                            `
                            UPDATE wallets
                            SET balance =
                                balance + $1
                            WHERE id = $2
                            `,
                            [
                                amount,
                                recipient
                            ]
                        );

                        const txId =
                            makeTransactionId();

                        await client.query(
                            `
                            INSERT INTO transactions
                            (
                                id,
                                wallet_id,
                                type,
                                amount,
                                from_wallet,
                                to_wallet
                            )
                            VALUES
                            (
                                $1,
                                $2,
                                'send',
                                $3,
                                $2,
                                $4
                            )
                            `,
                            [
                                txId,
                                sender,
                                amount,
                                recipient
                            ]
                        );

                        await client.query(
                            `
                            INSERT INTO transactions
                            (
                                id,
                                wallet_id,
                                type,
                                amount,
                                from_wallet,
                                to_wallet
                            )
                            VALUES
                            (
                                $1,
                                $2,
                                'receive',
                                $3,
                                $4,
                                $2
                            )
                            `,
                            [
                                txId +
                                "-R",

                                recipient,

                                amount,

                                sender
                            ]
                        );

                        await client.query(
                            "COMMIT"
                        );

                        const updatedWallet =
                            await getWalletDetails(
                                sender
                            );

                        sendJSON(
                            res,
                            200,
                            {
                                success: true,

                                transaction: {
                                    id: txId,

                                    from: sender,

                                    to: recipient,

                                    amount
                                },

                                wallet:
                                    updatedWallet
                            }
                        );

                    } catch (error) {

                        await client.query(
                            "ROLLBACK"
                        );

                        sendJSON(
                            res,
                            400,
                            {
                                success: false,
                                error:
                                    error.message
                            }
                        );

                    } finally {

                        client.release();
                    }

                    return;
                }


                /* =========================
                   NOT FOUND
                ========================= */

                sendJSON(
                    res,
                    404,
                    {
                        success: false,
                        error:
                            "Not found"
                    }
                );

            } catch (error) {

                console.error(
                    "SERVER ERROR:",
                    error
                );

                sendJSON(
                    res,
                    500,
                    {
                        success: false,
                        error:
                            "Internal server error"
                    }
                );
            }
        }
    );


/* =========================
   START
========================= */

async function start() {

    try {

        await initDatabase();

        server.listen(
            PORT,
            "0.0.0.0",
            () => {

                console.log(
                    `SLX Network v1.5 running on port ${PORT}`
                );
            }
        );

    } catch (error) {

        console.error(
            "Database startup error:",
            error
        );

        process.exit(1);
    }
}

start();