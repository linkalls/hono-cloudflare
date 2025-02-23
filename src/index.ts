import { signJWT } from "@cross/jwt";
import { Hono } from "hono";
import { privatekey } from "./shared/jwt";
import { userApp } from "./users/index";

interface User {
  username: string;
  password: string; // ハッシュ化されたパスワード
}

const users: User[] = [];

async function hashPassword(password: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return btoa(String.fromCharCode(...new Uint8Array(hash)));
}

async function verifyPassword(
  password: string,
  hashedPassword: string
): Promise<boolean> {
  const calculatedHash = await hashPassword(password);
  return calculatedHash === hashedPassword;
}

export { hashPassword, verifyPassword };

const app = new Hono();

// サインアップ
app.post("/signup", async (c) => {
  try {
    const { username, password } = await c.req.json();

    // 入力値のバリデーション
    if (!username || !password) {
      return c.json({ error: "Username and password are required" }, 400);
    }

    // 既存ユーザーのチェック
    const existingUser = users.find((u) => u.username === username);
    if (existingUser) {
      return c.json({ error: "Username already exists" }, 409);
    }

    // パスワードのハッシュ化
    const saltRounds = 10;
    const hashedPassword = await hashPassword(password);

    // ユーザーの保存
    users.push({
      username,
      password: hashedPassword,
    });

    // JWTトークンの生成
    const token = await signJWT({ username }, privatekey(c), {
      expiresIn: "1h",
    });

    return c.json({ token, username });
  } catch (error) {
    return c.json({ error: "Internal server error" }, 500);
  }
});

// ログイン
app.post("/login", async (c) => {
  try {
    const { username, password } = await c.req.json();

    // 入力値のバリデーション
    if (!username || !password) {
      return c.json({ error: "Username and password are required" }, 400);
    }

    // ユーザーの検索
    const user = users.find((u) => u.username === username);
    if (!user) {
      return c.json({ error: "Invalid credentials" }, 401);
    }

    // パスワードの検証
    const isValid = await verifyPassword(password, user.password);
    if (!isValid) {
      return c.json({ error: "Invalid credentials" }, 401);
    }

    // JWTトークンの生成
    const token = await signJWT({ username }, privatekey(c), {
      expiresIn: "1h",
    });

    return c.json({ token, username });
  } catch (error) {
    return c.json({ error: "Internal server error" }, 500);
  }
});

app.route("/auth", userApp);

export default app;
