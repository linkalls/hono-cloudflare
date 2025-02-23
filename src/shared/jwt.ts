import { Context } from "hono";

// .dev.varsから環境変数を取得
export const privatekey = (c: Context) =>
  (c.env.JWT_SECRET_KEY as string) || "12345678901234567890123456789012";
