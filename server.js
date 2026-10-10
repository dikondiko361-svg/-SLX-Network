import os
import json
import time
import uuid
import hmac
import hashlib
import secrets
import sqlite3
from datetime import datetime, timezone

from flask import Flask, request, jsonify, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps


# =========================================================
# SLX NETWORK v1.8.2
# Backend / Testnet
# =========================================================

VERSION = "1.8.2"
NETWORK = "SLX-Testnet"

TRANSFER_FEE = 0.1
FAUCET_AMOUNT = 10.0
FAUCET_COOLDOWN = 24 * 60 * 60

MAX_SUPPLY = 1_000_000_000.0

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "slx_network.db")

SECRET_KEY = os.environ.get(
    "SLX_SECRET_KEY",
    "slx-v1.8.2-change-this-secret-key"
)

app = Flask(__name__, static_folder=None)


# =========================================================
# DATABASE
# =========================================================

def db():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_db():
    connection = db()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            recovery_code TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS wallets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            address TEXT UNIQUE NOT NULL,
            balance REAL NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tx_hash TEXT UNIQUE NOT NULL,
            type TEXT NOT NULL,
            from_wallet TEXT,
            to_wallet TEXT,
            amount REAL NOT NULL,
            fee REAL NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            block_id INTEGER
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blocks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            block_index INTEGER UNIQUE NOT NULL,
            timestamp TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            hash TEXT UNIQUE NOT NULL,
            transaction_count INTEGER NOT NULL DEFAULT 0
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS faucet_claims (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            wallet_id INTEGER NOT NULL,
            claimed_at INTEGER NOT NULL,
            FOREIGN KEY(wallet_id) REFERENCES wallets(id) ON DELETE CASCADE
        )
    """)

    connection.commit()

    # Genesis block
    existing = cursor.execute(
        "SELECT id FROM blocks WHERE block_index = 0"
    ).fetchone()

    if not existing:
        timestamp = now_iso()
        previous_hash = "0" * 64

        block_hash = calculate_block_hash(
            0,
            timestamp,
            previous_hash,
            0
        )

        cursor.execute("""
            INSERT INTO blocks
            (block_index, timestamp, previous_hash, hash, transaction_count)
            VALUES (?, ?, ?, ?, ?)
        """, (
            0,
            timestamp,
            previous_hash,
            block_hash,
            0
        ))

        connection.commit()

    connection.close()


# =========================================================
# HELPERS
# =========================================================

def now_iso():
    return datetime.now(timezone.utc).isoformat()


def json_error(message, status=400):
    return jsonify({
        "error": message,
        "message": message
    }), status


def clean_username(username):
    return str(username or "").strip()


def valid_username(username):
    if not username:
        return False

    if len(username) < 3 or len(username) > 32:
        return False

    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"

    return all(char in allowed for char in username)


def valid_password(password):
    return isinstance(password, str) and len(password) >= 6


def generate_recovery_code():
    return secrets.token_hex(4).upper()


def generate_wallet_address():
    random_part = secrets.token_hex(16).upper()
    return "SLXC" + random_part


def generate_tx_hash(data):
    raw = json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":")
    ).encode()

    return hashlib.sha256(raw).hexdigest()


def calculate_block_hash(
    block_index,
    timestamp,
    previous_hash,
    transaction_count
):
    raw = (
        f"{block_index}|"
        f"{timestamp}|"
        f"{previous_hash}|"
        f"{transaction_count}"
    ).encode()

    return hashlib.sha256(raw).hexdigest()


def create_token(user_id):
    random_part = secrets.token_urlsafe(32)

    raw = f"{user_id}:{random_part}:{time.time()}".encode()

    signature = hmac.new(
        SECRET_KEY.encode(),
        raw,
        hashlib.sha256
    ).hexdigest()

    token = secrets.token_urlsafe(32) + "." + signature

    connection = db()

    connection.execute("""
        INSERT INTO sessions(token, user_id, created_at)
        VALUES (?, ?, ?)
    """, (
        token,
        user_id,
        int(time.time())
    ))

    connection.commit()
    connection.close()

    return token


def get_user_from_token(token):
    if not token:
        return None

    connection = db()

    row = connection.execute("""
        SELECT users.*
        FROM sessions
        JOIN users ON users.id = sessions.user_id
        WHERE sessions.token = ?
    """, (token,)).fetchone()

    connection.close()

    return row


def get_bearer_token():
    header = request.headers.get("Authorization", "")

    if not header.startswith("Bearer "):
        return None

    return header[7:].strip()


def auth_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):

        token = get_bearer_token()

        user = get_user_from_token(token)

        if not user:
            return json_error(
                "Требуется авторизация.",
                401
            )

        request.current_user = user
        request.current_token = token

        return function(*args, **kwargs)

    return wrapper


def user_json(user):
    return {
        "id": user["id"],
        "username": user["username"],
        "created_at": user["created_at"]
    }


def wallet_json(wallet):
    return {
        "id": wallet["id"],
        "user_id": wallet["user_id"],
        "address": wallet["address"],
        "balance": round(float(wallet["balance"]), 8),
        "created_at": wallet["created_at"]
    }


def find_wallet_for_user(wallet_id, user_id):
    connection = db()

    wallet = connection.execute("""
        SELECT *
        FROM wallets
        WHERE id = ? AND user_id = ?
    """, (
        wallet_id,
        user_id
    )).fetchone()

    connection.close()

    return wallet


def get_total_supply():
    connection = db()

    row = connection.execute("""
        SELECT COALESCE(SUM(balance), 0) AS total
        FROM wallets
    """).fetchone()

    connection.close()

    return float(row["total"] or 0)


# =========================================================
# BLOCKCHAIN
# =========================================================

def add_block(transaction_count=0):
    connection = db()

    previous = connection.execute("""
        SELECT *
        FROM blocks
        ORDER BY block_index DESC
        LIMIT 1
    """).fetchone()

    block_index = int(previous["block_index"]) + 1
    timestamp = now_iso()
    previous_hash = previous["hash"]

    block_hash = calculate_block_hash(
        block_index,
        timestamp,
        previous_hash,
        transaction_count
    )

    connection.execute("""
        INSERT INTO blocks
        (
            block_index,
            timestamp,
            previous_hash,
            hash,
            transaction_count
        )
        VALUES (?, ?, ?, ?, ?)
    """, (
        block_index,
        timestamp,
        previous_hash,
        block_hash,
        transaction_count
    ))

    connection.commit()
    connection.close()

    return block_hash


def verify_chain():
    connection = db()

    blocks = connection.execute("""
        SELECT *
        FROM blocks
        ORDER BY block_index ASC
    """).fetchall()

    connection.close()

    if not blocks:
        return False

    previous_hash = "0" * 64

    for block in blocks:

        expected = calculate_block_hash(
            block["block_index"],
            block["timestamp"],
            previous_hash,
            block["transaction_count"]
        )

        if block["previous_hash"] != previous_hash:
            return False

        if block["hash"] != expected:
            return False

        previous_hash = block["hash"]

    return True


# =========================================================
# ROOT
# =========================================================

@app.route("/")
def index():
    return send_from_directory(BASE_DIR, "index.html")


@app.route("/health")
def health():
    return jsonify({
        "status": "online",
        "version": VERSION,
        "network": NETWORK
    })


# =========================================================
# AUTH
# =========================================================

@app.post("/api/auth/register")
def register():

    data = request.get_json(silent=True) or {}

    username = clean_username(data.get("username"))
    password = data.get("password", "")

    if not valid_username(username):
        return json_error(
            "Имя пользователя должно содержать 3–32 символа."
        )

    if not valid_password(password):
        return json_error(
            "Пароль должен содержать минимум 6 символов."
        )

    connection = db()

    exists = connection.execute("""
        SELECT id
        FROM users
        WHERE LOWER(username) = LOWER(?)
    """, (username,)).fetchone()

    if exists:
        connection.close()
        return json_error(
            "Такой пользователь уже существует.",
            409
        )

    recovery_code = generate_recovery_code()

    password_hash = generate_password_hash(password)

    created_at = now_iso()

    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO users
        (
            username,
            password_hash,
            recovery_code,
            created_at
        )
        VALUES (?, ?, ?, ?)
    """, (
        username,
        password_hash,
        recovery_code,
        created_at
    ))

    user_id = cursor.lastrowid

    # Первый кошелек
    address = generate_wallet_address()

    cursor.execute("""
        INSERT INTO wallets
        (
            user_id,
            address,
            balance,
            created_at
        )
        VALUES (?, ?, ?, ?)
    """, (
        user_id,
        address,
        0,
        created_at
    ))

    connection.commit()

    user = connection.execute("""
        SELECT *
        FROM users
        WHERE id = ?
    """, (user_id,)).fetchone()

    connection.close()

    token = create_token(user_id)

    return jsonify({
        "ok": True,
        "token": token,
        "accessToken": token,
        "recoveryCode": recovery_code,
        "recovery_code": recovery_code,
        "user": user_json(user)
    })


@app.post("/api/auth/login")
def login():

    data = request.get_json(silent=True) or {}

    username = clean_username(data.get("username"))
    password = data.get("password", "")

    connection = db()

    user = connection.execute("""
        SELECT *
        FROM users
        WHERE LOWER(username) = LOWER(?)
    """, (username,)).fetchone()

    connection.close()

    if not user:
        return json_error(
            "Неверный логин или пароль.",
            401
        )

    if not check_password_hash(
        user["password_hash"],
        password
    ):
        return json_error(
            "Неверный логин или пароль.",
            401
        )

    token = create_token(user["id"])

    return jsonify({
        "ok": True,
        "token": token,
        "accessToken": token,
        "user": user_json(user)
    })


@app.get("/api/auth/me")
@auth_required
def me():

    return jsonify({
        "user": user_json(request.current_user)
    })


@app.post("/api/auth/logout")
@auth_required
def logout():

    connection = db()

    connection.execute("""
        DELETE FROM sessions
        WHERE token = ?
    """, (
        request.current_token,
    ))

    connection.commit()
    connection.close()

    return jsonify({
        "ok": True
    })


@app.post("/api/auth/password/change")
@auth_required
def change_password():

    data = request.get_json(silent=True) or {}

    current_password = data.get("currentPassword", "")
    new_password = data.get("newPassword", "")

    user = request.current_user

    if not check_password_hash(
        user["password_hash"],
        current_password
    ):
        return json_error(
            "Текущий пароль неверный.",
            400
        )

    if not valid_password(new_password):
        return json_error(
            "Новый пароль должен содержать минимум 6 символов."
        )

    password_hash = generate_password_hash(new_password)

    connection = db()

    connection.execute("""
        UPDATE users
        SET password_hash = ?
        WHERE id = ?
    """, (
        password_hash,
        user["id"]
    ))

    connection.commit()
    connection.close()

    # Новый токен
    new_token = create_token(user["id"])

    return jsonify({
        "ok": True,
        "token": new_token,
        "accessToken": new_token
    })


@app.post("/api/auth/recovery/reset")
def recovery_reset():

    data = request.get_json(silent=True) or {}

    username = clean_username(data.get("username"))
    recovery_code = str(
        data.get("recoveryCode", "")
    ).strip().upper()

    new_password = data.get(
        "newPassword",
        ""
    )

    if not valid_password(new_password):
        return json_error(
            "Новый пароль должен содержать минимум 6 символов."
        )

    connection = db()

    user = connection.execute("""
        SELECT *
        FROM users
        WHERE LOWER(username) = LOWER(?)
    """, (username,)).fetchone()

    if not user:
        connection.close()
        return json_error(
            "Пользователь не найден.",
            404
        )

    if not hmac.compare_digest(
        user["recovery_code"],
        recovery_code
    ):
        connection.close()
        return json_error(
            "Неверный код восстановления.",
            400
        )

    password_hash = generate_password_hash(
        new_password
    )

    connection.execute("""
        UPDATE users
        SET password_hash = ?
        WHERE id = ?
    """, (
        password_hash,
        user["id"]
    ))

    connection.commit()
    connection.close()

    token = create_token(user["id"])

    return jsonify({
        "ok": True,
        "token": token,
        "accessToken": token
    })


# =========================================================
# WALLETS
# =========================================================

@app.get("/api/wallets")
@auth_required
def wallets():

    connection = db()

    rows = connection.execute("""
        SELECT *
        FROM wallets
        WHERE user_id = ?
        ORDER BY id ASC
    """, (
        request.current_user["id"],
    )).fetchall()

    connection.close()

    return jsonify({
        "wallets": [
            wallet_json(wallet)
            for wallet in rows
        ]
    })


@app.post("/api/wallet/create")
@auth_required
def create_wallet():

    address = generate_wallet_address()

    connection = db()

    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO wallets
        (
            user_id,
            address,
            balance,
            created_at
        )
        VALUES (?, ?, ?, ?)
    """, (
        request.current_user["id"],
        address,
        0,
        now_iso()
    ))

    wallet_id = cursor.lastrowid

    connection.commit()

    wallet = connection.execute("""
        SELECT *
        FROM wallets
        WHERE id = ?
    """, (
        wallet_id,
    )).fetchone()

    connection.close()

    return jsonify({
        "ok": True,
        "wallet": wallet_json(wallet)
    })


@app.post("/api/wallet/select")
@auth_required
def select_wallet():

    data = request.get_json(silent=True) or {}

    wallet_id = data.get("walletId")

    if not wallet_id:
        return json_error(
            "Не указан кошелёк."
        )

    wallet = find_wallet_for_user(
        wallet_id,
        request.current_user["id"]
    )

    if not wallet:
        return json_error(
            "Кошелёк не найден.",
            404
        )

    return jsonify({
        "ok": True,
        "wallet": wallet_json(wallet)
    })


@app.get("/api/wallet/<int:wallet_id>")
@auth_required
def wallet_details(wallet_id):

    wallet = find_wallet_for_user(
        wallet_id,
        request.current_user["id"]
    )

    if not wallet:
        return json_error(
            "Кошелёк не найден.",
            404
        )

    connection = db()

    transactions = connection.execute("""
        SELECT *
        FROM transactions
        WHERE from_wallet = ?
           OR to_wallet = ?
        ORDER BY id DESC
        LIMIT 100
    """, (
        wallet["address"],
        wallet["address"]
    )).fetchall()

    connection.close()

    return jsonify({
        **wallet_json(wallet),
        "wallet": wallet_json(wallet),
        "transactions": [
            dict(tx)
            for tx in transactions
        ],
        "history": [
            dict(tx)
            for tx in transactions
        ]
    })


# =========================================================
# SEND
# =========================================================

@app.post("/api/send")
@auth_required
def send():

    data = request.get_json(silent=True) or {}

    from_wallet_id = data.get("fromWalletId")
    to_address = str(
        data.get("toAddress", "")
    ).strip().upper()

    try:
        amount = float(data.get("amount"))
    except:
        return json_error(
            "Некорректная сумма."
        )

    if not from_wallet_id:
        return json_error(
            "Не указан отправляющий кошелёк."
        )

    if amount <= 0:
        return json_error(
            "Сумма должна быть больше 0."
        )

    if amount > 1_000_000_000:
        return json_error(
            "Слишком большая сумма."
        )

    # SLX address
    if len(to_address) != 36 or not to_address.startswith("SLXC"):
        return json_error(
            "Некорректный адрес SLX."
        )

    try:
        int(to_address[4:], 16)
    except:
        return json_error(
            "Некорректный адрес SLX."
        )

    from_wallet = find_wallet_for_user(
        from_wallet_id,
        request.current_user["id"]
    )

    if not from_wallet:
        return json_error(
            "Кошелёк отправителя не найден.",
            404
        )

    if to_address == from_wallet["address"]:
        return json_error(
            "Нельзя отправить самому себе."
        )

    connection = db()

    to_wallet = connection.execute("""
        SELECT *
        FROM wallets
        WHERE address = ?
    """, (
        to_address,
    )).fetchone()

    if not to_wallet:
        connection.close()
        return json_error(
            "Кошелёк получателя не найден.",
            404
        )

    balance = float(from_wallet["balance"])

    if amount + TRANSFER_FEE > balance:
        connection.close()
        return json_error(
            "Недостаточно SLX с учётом комиссии."
        )

    timestamp = now_iso()

    tx_hash = generate_tx_hash({
        "type": "TRANSFER",
        "from": from_wallet["address"],
        "to": to_address,
        "amount": amount,
        "fee": TRANSFER_FEE,
        "timestamp": timestamp,
        "nonce": secrets.token_hex(8)
    })

    connection.execute("""
        UPDATE wallets
        SET balance = balance - ?
        WHERE id = ?
    """, (
        amount + TRANSFER_FEE,
        from_wallet["id"]
    ))

    connection.execute("""
        UPDATE wallets
        SET balance = balance + ?
        WHERE id = ?
    """, (
        amount,
        to_wallet["id"]
    ))

    connection.execute("""
        INSERT INTO transactions
        (
            tx_hash,
            type,
            from_wallet,
            to_wallet,
            amount,
            fee,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        tx_hash,
        "TRANSFER",
        from_wallet["address"],
        to_address,
        amount,
        TRANSFER_FEE,
        timestamp
    ))

    connection.commit()

    tx_id = connection.execute(
        "SELECT last_insert_rowid()"
    ).fetchone()[0]

    connection.close()

    block_hash = add_block(1)

    connection = db()

    connection.execute("""
        UPDATE transactions
        SET block_id = (
            SELECT id
            FROM blocks
            WHERE hash = ?
        )
        WHERE id = ?
    """, (
        block_hash,
        tx_id
    ))

    connection.commit()
    connection.close()

    return jsonify({
        "ok": True,
        "tx": {
            "id": tx_id,
            "hash": tx_hash,
            "type": "TRANSFER",
            "from_wallet": from_wallet["address"],
            "to_wallet": to_address,
            "amount": amount,
            "fee": TRANSFER_FEE,
            "created_at": timestamp
        }
    })


# =========================================================
# FAUCET
# =========================================================

@app.post("/api/faucet")
@auth_required
def faucet():

    data = request.get_json(silent=True) or {}

    wallet_id = data.get("walletId")

    wallet = find_wallet_for_user(
        wallet_id,
        request.current_user["id"]
    )

    if not wallet:
        return json_error(
            "Кошелёк не найден.",
            404
        )

    connection = db()

    last_claim = connection.execute("""
        SELECT claimed_at
        FROM faucet_claims
        WHERE wallet_id = ?
        ORDER BY claimed_at DESC
        LIMIT 1
    """, (
        wallet["id"],
    )).fetchone()

    now = int(time.time())

    if last_claim:

        elapsed = now - int(
            last_claim["claimed_at"]
        )

        if elapsed < FAUCET_COOLDOWN:

            remaining = FAUCET_COOLDOWN - elapsed

            connection.close()

            return json_error(
                f"Faucet будет доступен через {remaining} секунд.",
                429
            )

    current_supply = get_total_supply()

    if current_supply + FAUCET_AMOUNT > MAX_SUPPLY:
        connection.close()

        return json_error(
            "Достигнут максимальный Supply.",
            400
        )

    timestamp = now_iso()

    tx_hash = generate_tx_hash({
        "type": "FAUCET",
        "wallet": wallet["address"],
        "amount": FAUCET_AMOUNT,
        "timestamp": timestamp,
        "nonce": secrets.token_hex(8)
    })

    connection.execute("""
        UPDATE wallets
        SET balance = balance + ?
        WHERE id = ?
    """, (
        FAUCET_AMOUNT,
        wallet["id"]
    ))

    connection.execute("""
        INSERT INTO faucet_claims
        (
            wallet_id,
            claimed_at
        )
        VALUES (?, ?)
    """, (
        wallet["id"],
        now
    ))

    connection.execute("""
        INSERT INTO transactions
        (
            tx_hash,
            type,
            from_wallet,
            to_wallet,
            amount,
            fee,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        tx_hash,
        "FAUCET",
        "FAUCET",
        wallet["address"],
        FAUCET_AMOUNT,
        0,
        timestamp
    ))

    connection.commit()

    tx_id = connection.execute(
        "SELECT last_insert_rowid()"
    ).fetchone()[0]

    connection.close()

    block_hash = add_block(1)

    connection = db()

    connection.execute("""
        UPDATE transactions
        SET block_id = (
            SELECT id
            FROM blocks
            WHERE hash = ?
        )
        WHERE id = ?
    """, (
        block_hash,
        tx_id
    ))

    connection.commit()
    connection.close()

    return jsonify({
        "ok": True,
        "amount": FAUCET_AMOUNT,
        "cooldown": FAUCET_COOLDOWN,
        "txHash": tx_hash
    })


# =========================================================
# NETWORK STATUS
# =========================================================

@app.get("/api/status")
def status():

    connection = db()

    latest = connection.execute("""
        SELECT *
        FROM blocks
        ORDER BY block_index DESC
        LIMIT 1
    """).fetchone()

    connection.close()

    height = latest["block_index"] if latest else 0

    return jsonify({
        "status": "online",
        "online": True,
        "version": VERSION,
        "network": {
            "name": NETWORK,
            "version": VERSION,
            "status": "online",
            "height": height,
            "blockHeight": height,
            "latestBlock": height,
            "transferFee": TRANSFER_FEE,
            "transfer_fee": TRANSFER_FEE
        }
    })


@app.get("/api/economy")
def economy():

    total = get_total_supply()

    return jsonify({
        "totalSupply": round(total, 8),
        "total_supply": round(total, 8),
        "supply": round(total, 8),
        "maxSupply": MAX_SUPPLY,
        "max_supply": MAX_SUPPLY,
        "transferFee": TRANSFER_FEE,
        "transfer_fee": TRANSFER_FEE,
        "faucetAmount": FAUCET_AMOUNT
    })


# =========================================================
# BLOCKS
# =========================================================

@app.get("/api/blocks")
def blocks():

    connection = db()

    rows = connection.execute("""
        SELECT *
        FROM blocks
        ORDER BY block_index DESC
        LIMIT 100
    """).fetchall()

    connection.close()

    return jsonify({
        "blocks": [
            dict(row)
            for row in rows
        ]
    })


@app.post("/api/chain/verify")
@app.get("/api/chain/verify")
def chain_verify():

    valid = verify_chain()

    return jsonify({
        "valid": valid,
        "verified": valid,
        "status": "valid" if valid else "invalid"
    })


# =========================================================
# CATCH ERRORS
# =========================================================

@app.errorhandler(404)
def not_found(error):

    if request.path.startswith("/api/"):
        return json_error(
            "API endpoint не найден.",
            404
        )

    return error


@app.errorhandler(500)
def server_error(error):

    return jsonify({
        "error": "Internal server error",
        "message": "Ошибка сервера SLX Network."
    }), 500


# =========================================================
# START
# =========================================================

init_db()


if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            5000
        )
    )

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )