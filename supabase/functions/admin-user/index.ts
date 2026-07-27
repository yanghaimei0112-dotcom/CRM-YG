// admin-user —— 管理员账号管理（删除成员 / 重置密码）
// 调用契约：POST { action: "delete" | "password", userId, password? }
// 鉴权：前端带 apikey + 用户 access_token（verify_jwt=false，函数内自行校验调用者身份与管理员角色）
import { createClient } from "npm:@supabase/supabase-js@2";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...cors, "Content-Type": "application/json" },
  });
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  try {
    const token = (req.headers.get("Authorization") || "").replace("Bearer ", "");
    if (!token) return json({ error: "未登录" }, 401);

    const url = Deno.env.get("SUPABASE_URL")!;
    const anon = Deno.env.get("SUPABASE_ANON_KEY")!;
    const service = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

    // 1) 验证调用者身份（用调用者自己的 token 取用户）
    const callerClient = createClient(url, anon, {
      global: { headers: { Authorization: `Bearer ${token}` } },
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const { data: { user }, error: ue } = await callerClient.auth.getUser();
    if (ue || !user) return json({ error: "登录状态无效，请重新登录" }, 401);

    // 2) 校验调用者是管理员（service role 查 profiles，绕过 RLS）
    const admin = createClient(url, service, {
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const { data: prof } = await admin.from("profiles").select("role").eq("id", user.id).maybeSingle();
    if (!prof || prof.role !== "admin") return json({ error: "仅管理员可执行此操作" }, 403);

    const body = await req.json().catch(() => ({}));
    const { action, userId, password } = body;
    if (!userId) return json({ error: "缺少 userId" }, 400);

    if (action === "delete") {
      if (userId === user.id) return json({ error: "不能删除当前登录的自己" }, 400);
      const { error } = await admin.auth.admin.deleteUser(userId);
      if (error) return json({ error: error.message }, 400);
      return json({ ok: true });
    }

    if (action === "password") {
      if (!password || String(password).length < 6) return json({ error: "密码至少 6 位" }, 400);
      const { error } = await admin.auth.admin.updateUserById(userId, { password: String(password) });
      if (error) return json({ error: error.message }, 400);
      return json({ ok: true });
    }

    return json({ error: "未知操作" }, 400);
  } catch (e) {
    return json({ error: String((e as Error)?.message || e) }, 500);
  }
});
