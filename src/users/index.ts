import { validateJWT } from "@cross/jwt";
import { Context, Hono, Next } from "hono";
import { privatekey } from "../shared/jwt";

type UserType = {
  username: string;
};

const userApp = new Hono<{
  Variables: {
    user: UserType;
  };
}>();

export const jwtAuthMiddleware = async (c: Context, next: Next) => {
  const authHeader = c.req.header("Authorization");
  if (!authHeader) {
    return c.json({ error: "No token provided" }, 401);
  }

  const token = authHeader.replace("Bearer ", "");

  try {
    // トークンからユーザー情報を取得
    const payload = await validateJWT(token, privatekey(c));
    // ユーザー情報をコンテキストに保存
    c.set("user", payload);
    await next();
  } catch (err) {
    return c.json({ error: "Invalid token" }, 401);
  }
};

userApp.use("*", jwtAuthMiddleware);

userApp.get("/me", async (c) => {
  // コンテキストからユーザー情報を取得
  console.log(c.get("user"));
  const user = c.get("user");
  return c.json({
    username: user.username,
    // 他のユーザー情報もここで返却可能
  });
});

export { userApp };
