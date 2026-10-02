const http = require("http");
const fs = require("fs");
const path = require("path");

const PORT = process.env.PORT || 3000;

let state = {
  balance: 1000,
  wallet: "SLX-TEST-7F92A1C4",
  transactions: []
};

function sendJSON(res, data, status = 200) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Access-Control-Allow-Origin": "*"
  });

  res.end(JSON.stringify(data));
}

function sendHTML(res) {
  const file = path.join(__dirname, "index.html");

  fs.readFile(file, "utf8", (err, html) => {
    if (err) {
      res.writeHead(500, {
        "Content-Type": "text/plain; charset=utf-8"
      });

      res.end("SLX: index.html not found");
      return;
    }

    res.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8"
    });

    res.end(html);
  });
}

function getBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";

    req.on("data", chunk => {
      body += chunk;
    });

    req.on("end", () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch {
        reject(new Error("Invalid JSON"));
      }
    });

    req.on("error", reject);
  });
}

const server = http.createServer(async (req, res) => {

  // Главная страница
  if (req.method === "GET" && req.url === "/") {
    sendHTML(res);
    return;
  }

  // Проверка состояния сети
  if (req.method === "GET" && req.url === "/api/status") {
    sendJSON(res, {
      success: true,
      network: "SLX Testnet",
      version: "0.7",
      status: "online",
      wallet: state.wallet,
      balance: state.balance,
      transactions: state.transactions
    });

    return;
  }

  // Отправка SLX
  if (req.method === "POST" && req.url === "/api/send") {
    try {
      const body = await getBody(req);
      const amount = Number(body.amount);
      const recipient = String(body.recipient || "");

      if (!Number.isFinite(amount) || amount <= 0) {
        sendJSON(res, {
          success: false,
          error: "Invalid amount"
        }, 400);

        return;
      }

      if (!recipient) {
        sendJSON(res, {
          success: false,
          error: "Recipient is required"
        }, 400);

        return;
      }

      if (amount > state.balance) {
        sendJSON(res, {
          success: false,
          error: "Insufficient SLX balance"
        }, 400);

        return;
      }

      state.balance -= amount;

      const transaction = {
        id: "TX-" + Date.now(),
        type: "send",
        amount,
        recipient,
        time: new Date().toISOString()
      };

      state.transactions.unshift(transaction);

      sendJSON(res, {
        success: true,
        transaction,
        balance: state.balance
      });

    } catch {
      sendJSON(res, {
        success: false,
        error: "Invalid request"
      }, 400);
    }

    return;
  }

  // Получение тестовых SLX
  if (req.method === "POST" && req.url === "/api/faucet") {
    const amount = 100;

    state.balance += amount;

    const transaction = {
      id: "TX-" + Date.now(),
      type: "faucet",
      amount,
      time: new Date().toISOString()
    };

    state.transactions.unshift(transaction);

    sendJSON(res, {
      success: true,
      transaction,
      balance: state.balance
    });

    return;
  }

  // Неизвестный маршрут
  sendJSON(res, {
    success: false,
    error: "Not found"
  }, 404);
});

server.listen(PORT, () => {
  console.log(`SLX Network v0.7 running on port ${PORT}`);
});