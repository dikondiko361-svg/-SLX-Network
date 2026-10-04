const http = require("http");
const crypto = require("crypto");
const { Pool } = require("pg");

const PORT = process.env.PORT || 10000;

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL
        ? { rejectUnauthorized: false }
        : false
});


/* =========================
   HELPERS
========================= */

function json(res, status, data) {

    res.writeHead(status, {
        "Content-Type": "application/json; charset=utf-8",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS"
    });

    res.end(JSON.stringify(data));
}


function makeId() {
    return "SLX" +
        crypto.randomBytes(5)
            .toString("hex")
            .toUpperCase();
}


function makeAddress() {
    return "SLX-" +
        crypto.randomBytes(8)
            .toString("hex")
            .toUpperCase();
}


function makeUserId() {
    return "USER-" +
        crypto.randomBytes(8)
            .toString("hex")
            .toUpperCase();
}


function makeToken() {
    return crypto.randomBytes(32).toString("hex");
}


function hashPassword(password) {
    return crypto
        .createHash("sha256")
        .update(password)
        .digest("hex");
}


async function readBody(req) {

    return new Promise((resolve, reject) => {

        let body = "";

        req.on("data", chunk => {
            body += chunk;
        });

        req.on("end", () => {

            if (!body) {
                resolve({});
                return;
            }

            try {
                resolve(JSON.parse(body));
            } catch {
                reject(new Error("Неверный JSON."));
            }
        });

        req.on("error", reject);
    });
}


/* =========================
   SESSIONS
========================= */

const sessions = new Map();


function getToken(req) {

    const header =
        req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
        return null;
    }

    return header.substring(7);
}


async function getUser(req) {

    const token = getToken(req);

    if (!token) {
        return null;
    }

    const userId = sessions.get(token);

    if (!userId) {
        return null;
    }

    const result = await pool.query(
        `
        SELECT id, username, created_at
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
   DATABASE
========================= */

async function initDatabase() {

    await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )
    `);


    await pool.query(`
        CREATE TABLE IF NOT EXISTS wallets (
            id TEXT PRIMARY KEY,
            owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            address TEXT UNIQUE NOT NULL,
            balance NUMERIC(30,8) NOT NULL DEFAULT 1000,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )
    `);


    await pool.query(`
        CREATE TABLE IF NOT EXISTS transactions (
            id TEXT PRIMARY KEY,
            wallet_id TEXT NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
            type TEXT NOT NULL,
            amount NUMERIC(30,8) NOT NULL,
            from_wallet TEXT,
            to_wallet TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )
    `);

    console.log("PostgreSQL database ready.");
}


/* =========================
   WALLET
========================= */

async function getWallet(walletId) {

    const result = await pool.query(
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

    if (!result.rows.length) {
        return null;
    }

    return result.rows[0];
}


async function getWalletWithTransactions(walletId) {

    const wallet = await getWallet(walletId);

    if (!wallet) {
        return null;
    }

    const transactions =
        await pool.query(
            `
            SELECT
                id,
                type,
                amount,
                from_wallet AS "from",
                to_wallet AS "to",
                created_at AS time
            FROM transactions
            WHERE wallet_id = $1
            ORDER BY created_at DESC
            `,
            [walletId]
        );


    return {
        id: wallet.id,
        address: wallet.address,
        balance: Number(wallet.balance),
        createdAt: wallet.created_at,
        transactions: transactions.rows.map(tx => ({
            id: tx.id,
            type: tx.type,
            amount: Number(tx.amount),
            from: tx.from,
            to: tx.to,
            time: tx.time
        }))
    };
}


/* =========================
   SERVER
========================= */

const server = http.createServer(
    async (req, res) => {

        if (req.method === "OPTIONS") {

            res.writeHead(204, {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Headers":
                    "Content-Type, Authorization",
                "Access-Control-Allow-Methods":
                    "GET, POST, OPTIONS"
            });

            res.end();
            return;
        }


        try {

            const url =
                new URL(
                    req.url,
                    `http://${req.headers.host}`
                );

            const pathname =
                url.pathname;


            /* =====================
               HOME
            ===================== */

            if (
                req.method === "GET" &&
                pathname === "/"
            ) {

                const fs = require("fs");
                const path = require("path");

                const file =
                    path.join(
                        __dirname,
                        "index.html"
                    );

                if (!fs.existsSync(file)) {

                    json(res, 404, {
                        success: false,
                        error: "index.html не найден."
                    });

                    return;
                }

                res.writeHead(200, {
                    "Content-Type":
                        "text/html; charset=utf-8"
                });

                res.end(
                    fs.readFileSync(file)
                );

                return;
            }


            /* =====================
               STATUS
            ===================== */

            if (
                req.method === "GET" &&
                pathname === "/api/status"
            ) {

                const accounts =
                    await pool.query(
                        `SELECT COUNT(*)::int AS count FROM users`
                    );

                const wallets =
                    await pool.query(
                        `SELECT COUNT(*)::int AS count FROM wallets`
                    );

                json(res, 200, {
                    success: true,
                    network: "SLX Testnet",
                    version: "1.4",
                    accounts:
                        accounts.rows[0].count,
                    wallets:
                        wallets.rows[0].count
                });

                return;
            }


            /* =====================
               REGISTER
            ===================== */

            if (
                req.method === "POST" &&
                pathname === "/api/auth/register"
            ) {

                const body =
                    await readBody(req);

                const username =
                    String(
                        body.username || ""
                    ).trim();

                const password =
                    String(
                        body.password || ""
                    );


                if (!username || !password) {

                    json(res, 400, {
                        success: false,
                        error:
                            "Введите имя пользователя и пароль."
                    });

                    return;
                }


                const existing =
                    await pool.query(
                        `
                        SELECT id
                        FROM users
                        WHERE LOWER(username) = LOWER($1)
                        `,
                        [username]
                    );


                if (existing.rows.length) {

                    json(res, 409, {
                        success: false,
                        error:
                            "Такой пользователь уже существует."
                    });

                    return;
                }


                const userId =
                    makeUserId();

                const walletId =
                    makeId();

                const address =
                    makeAddress();

                const passwordHash =
                    hashPassword(password);


                const client =
                    await pool.connect();

                try {

                    await client.query("BEGIN");


                    await client.query(
                        `
                        INSERT INTO users
                        (id, username, password_hash)
                        VALUES ($1, $2, $3)
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
                        (id, owner_id, address, balance)
                        VALUES ($1, $2, $3, 1000)
                        `,
                        [
                            walletId,
                            userId,
                            address
                        ]
                    );


                    await client.query("COMMIT");

                } catch (error) {

                    await client.query("ROLLBACK");
                    throw error;

                } finally {

                    client.release();
                }


                const token =
                    makeToken();

                sessions.set(
                    token,
                    userId
                );


                json(res, 200, {

                    success: true,

                    token,

                    user: {
                        id: userId,
                        username,
                        walletId,
                        walletIds: [walletId]
                    },

                    wallet: {
                        id: walletId,
                        address,
                        balance: 1000,
                        transactions: []
                    }
                });

                return;
            }


            /* =====================
               LOGIN
            ===================== */

            if (
                req.method === "POST" &&
                pathname === "/api/auth/login"
            ) {

                const body =
                    await readBody(req);

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
                        WHERE LOWER(username) = LOWER($1)
                        `,
                        [username]
                    );


                if (!result.rows.length) {

                    json(res, 401, {
                        success: false,
                        error:
                            "Неверное имя пользователя или пароль."
                    });

                    return;
                }


                const user =
                    result.rows[0];

                const passwordHash =
                    hashPassword(password);


                if (
                    user.password_hash !==
                    passwordHash
                ) {

                    json(res, 401, {
                        success: false,
                        error:
                            "Неверное имя пользователя или пароль."
                    });

                    return;
                }


                const walletResult =
                    await pool.query(
                        `
                        SELECT id
                        FROM wallets
                        WHERE owner_id = $1
                        ORDER BY created_at ASC
                        `,
                        [user.id]
                    );


                const walletIds =
                    walletResult.rows.map(
                        row => row.id
                    );


                const token =
                    makeToken();

                sessions.set(
                    token,
                    user.id
                );


                json(res, 200, {

                    success: true,

                    token,

                    user: {
                        id: user.id,
                        username: user.username,
                        walletId:
                            walletIds[0] || null,
                        walletIds
                    }
                });

                return;
            }


            /* =====================
               ME
            ===================== */

            if (
                req.method === "GET" &&
                pathname === "/api/auth/me"
            ) {

                const user =
                    await getUser(req);

                if (!user) {

                    json(res, 401, {
                        success: false,
                        error:
                            "Необходим вход."
                    });

                    return;
                }


                const wallets =
                    await pool.query(
                        `
                        SELECT id
                        FROM wallets
                        WHERE owner_id = $1
                        ORDER BY created_at ASC
                        `,
                        [user.id]
                    );


                const walletIds =
                    wallets.rows.map(
                        row => row.id
                    );


                json(res, 200, {

                    success: true,

                    user: {
                        id: user.id,
                        username: user.username,
                        walletId:
                            walletIds[0] || null,
                        walletIds
                    }
                });

                return;
            }


            /* =====================
               LOGOUT
            ===================== */

            if (
                req.method === "POST" &&
                pathname === "/api/auth/logout"
            ) {

                const token =
                    getToken(req);

                if (token) {
                    sessions.delete(token);
                }

                json(res, 200, {
                    success: true
                });

                return;
            }


            /* =====================
               MY WALLETS
            ===================== */

            if (
                req.method === "GET" &&
                pathname === "/api/wallets"
            ) {

                const user =
                    await getUser(req);

                if (!user) {

                    json(res, 401, {
                        success: false,
                        error:
                            "Необходим вход."
                    });

                    return;
                }


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
                        [user.id]
                    );


                json(res, 200, {

                    success: true,

                    wallets:
                        result.rows.map(wallet => ({
                            id: wallet.id,
                            address: wallet.address,
                            balance:
                                Number(wallet.balance),
                            createdAt:
                                wallet.created_at
                        }))
                });

                return;
            }


            /* =====================
               CREATE WALLET
            ===================== */

            if (
                req.method === "POST" &&
                pathname === "/api/wallet/create"
            ) {

                const user =
                    await getUser(req);

                if (!user) {

                    json(res, 401, {
                        success: false,
                        error:
                            "Необходим вход."
                    });

                    return;
                }


                const walletId =
                    makeId();

                const address =
                    makeAddress();


                await pool.query(
                    `
                    INSERT INTO wallets
                    (id, owner_id, address, balance)
                    VALUES ($1, $2, $3, 1000)
                    `,
                    [
                        walletId,
                        user.id,
                        address
                    ]
                );


                const wallets =
                    await pool.query(
                        `
                        SELECT id
                        FROM wallets
                        WHERE owner_id = $1
                        ORDER BY created_at ASC
                        `,
                        [user.id]
                    );


                const walletIds =
                    wallets.rows.map(
                        row => row.id
                    );


                json(res, 200, {

                    success: true,

                    wallet: {
                        id: walletId,
                        address,
                        balance: 1000,
                        transactions: []
                    },

                    walletIds
                });

                return;
            }


            /* =====================
               SELECT WALLET
            ===================== */

            if (
                req.method === "POST" &&
                pathname === "/api/wallet/select"
            ) {

                const user =
                    await getUser(req);

                if (!user) {

                    json(res, 401, {
                        success: false,
                        error:
                            "Необходим вход."
                    });

                    return;
                }


                const body =
                    await readBody(req);

                const walletId =
                    String(
                        body.id || ""
                    ).trim();


                const wallet =
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


                if (!wallet.rows.length) {

                    json(res, 404, {
                        success: false,
                        error:
                            "Кошелёк не принадлежит этому аккаунту."
                    });

                    return;
                }


                const fullWallet =
                    await getWalletWithTransactions(
                        walletId
                    );


                json(res, 200, {
                    success: true,
                    wallet: fullWallet
                });

                return;
            }


            /* =====================
               GET WALLET
            ===================== */

            if (
                req.method === "GET" &&
                pathname.startsWith("/api/wallet/")
            ) {

                const user =
                    await getUser(req);

                if (!user) {

                    json(res, 401, {
                        success: false,
                        error:
                            "Необходим вход."
                    });

                    return;
                }


                const walletId =
                    decodeURIComponent(
                        pathname.substring(
                            "/api/wallet/".length
                        )
                    );


                const owner =
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


                if (!owner.rows.length) {

                    json(res, 404, {
                        success: false,
                        error:
                            "Кошелёк не найден."
                    });

                    return;
                }


                const wallet =
                    await getWalletWithTransactions(
                        walletId
                    );


                json(res, 200, {
                    success: true,
                    wallet
                });

                return;
            }


            /* =====================
               FIND WALLET
            ===================== */

            if (
                req.method === "GET" &&
                pathname.startsWith("/api/find/")
            ) {

                const walletId =
                    decodeURIComponent(
                        pathname.substring(
                            "/api/find/".length
                        )
                    );


                const wallet =
                    await getWallet(
                        walletId
                    );


                if (!wallet) {

                    json(res, 404, {
                        success: false,
                        error:
                            "Кошелёк не найден."
                    });

                    return;
                }


                json(res, 200, {

                    success: true,

                    wallet: {
                        id: wallet.id,
                        address: wallet.address,
                        balance:
                            Number(wallet.balance)
                    }
                });

                return;
            }


            /* =====================
               FAUCET
            ===================== */

            if (
                req.method === "POST" &&
                pathname === "/api/faucet"
            ) {

                const user =
                    await getUser(req);

                if (!user) {

                    json(res, 401, {
                        success: false,
                        error:
                            "Необходим вход."
                    });

                    return;
                }


                const body =
                    await readBody(req);

                const walletId =
                    String(
                        body.id || ""
                    ).trim();


                const client =
                    await pool.connect();

                try {

                    await client.query("BEGIN");


                    const wallet =
                        await client.query(
                            `
                            SELECT *
                            FROM wallets
                            WHERE id = $1
                            AND owner_id = $2
                            FOR UPDATE
                            `,
                            [
                                walletId,
                                user.id
                            ]
                        );


                    if (!wallet.rows.length) {

                        await client.query(
                            "ROLLBACK"
                        );

                        json(res, 404, {
                            success: false,
                            error:
                                "Кошелёк не найден."
                        });

                        return;
                    }


                    await client.query(
                        `
                        UPDATE wallets
                        SET balance = balance + 100
                        WHERE id = $1
                        `,
                        [walletId]
                    );


                    const txId =
                        "TX-" +
                        crypto.randomBytes(12)
                            .toString("hex")
                            .toUpperCase();


                    await client.query(
                        `
                        INSERT INTO transactions
                        (id, wallet_id, type, amount, to_wallet)
                        VALUES ($1, $2, 'faucet', 100, $2)
                        `,
                        [
                            txId,
                            walletId
                        ]
                    );


                    await client.query("COMMIT");


                    const updated =
                        await getWalletWithTransactions(
                            walletId
                        );


                    json(res, 200, {
                        success: true,
                        wallet: updated
                    });

                } catch (error) {

                    await client.query(
                        "ROLLBACK"
                    );

                    throw error;

                } finally {

                    client.release();
                }

                return;
            }


            /* =====================
               SEND SLX
            ===================== */

            if (
                req.method === "POST" &&
                pathname === "/api/send"
            ) {

                const user =
                    await getUser(req);

                if (!user) {

                    json(res, 401, {
                        success: false,
                        error:
                            "Необходим вход."
                    });

                    return;
                }


                const body =
                    await readBody(req);


                /*
                   Поддерживаем несколько
                   названий полей для совместимости.
                */

                const sender =
                    String(
                        body.sender ||
                        body.from ||
                        body.senderId ||
                        ""
                    ).trim();


                const recipient =
                    String(
                        body.recipient ||
                        body.to ||
                        body.recipientId ||
                        ""
                    ).trim();


                const amount =
                    Number(
                        body.amount
                    );


                if (!sender) {

                    json(res, 400, {
                        success: false,
                        error:
                            "Не указан отправитель."
                    });

                    return;
                }


                if (!recipient) {

                    json(res, 400, {
                        success: false,
                        error:
                            "Не указан получатель."
                    });

                    return;
                }


                if (
                    !Number.isFinite(amount) ||
                    amount <= 0
                ) {

                    json(res, 400, {
                        success: false,
                        error:
                            "Неверная сумма."
                    });

                    return;
                }


                if (sender === recipient) {

                    json(res, 400, {
                        success: false,
                        error:
                            "Нельзя отправить самому себе."
                    });

                    return;
                }


                const client =
                    await pool.connect();

                try {

                    await client.query("BEGIN");


                    /* Отправитель */

                    const senderResult =
                        await client.query(
                            `
                            SELECT *
                            FROM wallets
                            WHERE id = $1
                            AND owner_id = $2
                            FOR UPDATE
                            `,
                            [
                                sender,
                                user.id
                            ]
                        );


                    if (!senderResult.rows.length) {

                        await client.query(
                            "ROLLBACK"
                        );

                        json(res, 404, {
                            success: false,
                            error:
                                "Кошелёк отправителя не найден или не принадлежит вам."
                        });

                        return;
                    }


                    /* Получатель */

                    const recipientResult =
                        await client.query(
                            `
                            SELECT *
                            FROM wallets
                            WHERE id = $1
                            FOR UPDATE
                            `,
                            [recipient]
                        );


                    if (!recipientResult.rows.length) {

                        await client.query(
                            "ROLLBACK"
                        );

                        json(res, 404, {
                            success: false,
                            error:
                                "Кошелёк получателя не найден."
                        });

                        return;
                    }


                    const senderBalance =
                        Number(
                            senderResult.rows[0]
                                .balance
                        );


                    if (
                        senderBalance <
                        amount
                    ) {

                        await client.query(
                            "ROLLBACK"
                        );

                        json(res, 400, {
                            success: false,
                            error:
                                "Недостаточно SLX."
                        });

                        return;
                    }


                    /* Списываем */

                    await client.query(
                        `
                        UPDATE wallets
                        SET balance = balance - $1
                        WHERE id = $2
                        `,
                        [
                            amount,
                            sender
                        ]
                    );


                    /* Зачисляем */

                    await client.query(
                        `
                        UPDATE wallets
                        SET balance = balance + $1
                        WHERE id = $2
                        `,
                        [
                            amount,
                            recipient
                        ]
                    );


                    const txId =
                        "TX-" +
                        crypto.randomBytes(12)
                            .toString("hex")
                            .toUpperCase();


                    /* История отправителя */

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
                        ($1, $2, 'send', $3, $2, $4)
                        `,
                        [
                            txId + "-S",
                            sender,
                            amount,
                            recipient
                        ]
                    );


                    /* История получателя */

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
                        ($1, $2, 'receive', $3, $4, $2)
                        `,
                        [
                            txId + "-R",
                            recipient,
                            amount,
                            sender
                        ]
                    );


                    await client.query("COMMIT");


                    const updatedSender =
                        await getWalletWithTransactions(
                            sender
                        );


                    json(res, 200, {

                        success: true,

                        message:
                            "Перевод выполнен.",

                        wallet:
                            updatedSender,

                        transaction: {
                            id: txId,
                            sender,
                            recipient,
                            amount
                        }
                    });

                } catch (error) {

                    await client.query(
                        "ROLLBACK"
                    );

                    throw error;

                } finally {

                    client.release();
                }

                return;
            }


            /* =====================
               404
            ===================== */

            json(res, 404, {
                success: false,
                error: "Not found"
            });

        } catch (error) {

            console.error(
                "SERVER ERROR:",
                error
            );

            json(res, 500, {
                success: false,
                error:
                    "Ошибка сервера: " +
                    error.message
            });
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
                    `SLX Network running on port ${PORT}`
                );

            }
        );

    } catch (error) {

        console.error(
            "DATABASE START ERROR:",
            error
        );

        process.exit(1);
    }
}


start();