import { SignJWT, importPKCS8 } from "jose";
import http2 from "node:http2";
import { createClient } from "@supabase/supabase-js";

export const config = { api: { bodyParser: false } };

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", c => (data += c));
    req.on("end", () => { try { resolve(JSON.parse(data||"{}")); } catch(e){ reject(e); }});
    req.on("error", reject);
  });
}

async function makeApnsJwt(p8Pem, teamId, keyId) {
  const alg = "ES256";
  const key = await importPKCS8(p8Pem, alg);
  const now = Math.floor(Date.now()/1000);
  return await new SignJWT({})
    .setProtectedHeader({ alg, kid: keyId })
    .setIssuedAt(now)
    .setIssuer(teamId)
    .setExpirationTime(now + 50*60)
    .sign(key);
}

async function sendApns({ deviceToken, jwt, topic, payload, sandbox }) {
  const host = sandbox ? "api.sandbox.push.apple.com" : "api.push.apple.com";

  return new Promise((resolve, reject) => {
    const client = http2.connect(`https://${host}`);
    client.on("error", reject);

    const req = client.request({
      ":method": "POST",
      ":path": `/3/device/${deviceToken}`,
      "authorization": `bearer ${jwt}`,
      "apns-topic": topic,
      "apns-push-type": "alert",
      "content-type": "application/json"
    });

    let respData = "";
    req.setEncoding("utf8");
    req.on("data", chunk => (respData += chunk));
    req.on("end", () => { client.close(); resolve({ body: respData }); });
    req.on("error", e => { client.close(); reject(e); });

    req.end(JSON.stringify(payload));
  });
}

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).json({ error: "method_not_allowed" });

  // 可选：鉴权
  const relayToken = process.env.APNS_RELAY_TOKEN || null;
  if (relayToken) {
    const h = req.headers.authorization || "";
    const got = h.startsWith("Bearer ") ? h.slice(7) : null;
    if (!got || got !== relayToken) {
      return res.status(401).json({ error: "unauthorized" });
    }
  }

  let body;
  try { body = await readJsonBody(req); } catch{ return res.status(400).json({ error:"invalid_json" }); }
  const { recipientId, message, conversationId, senderId, senderNickname } = body;
  if (!recipientId) return res.status(400).json({ error:"recipientId_required" });

  const {
    SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY,
    APNS_P8_BASE64, APNS_KEY_ID, APNS_TEAM_ID, APNS_BUNDLE_ID, APNS_ENV
  } = process.env;

  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY)
    return res.status(500).json({ error:"supabase_env_missing" });

  if (!APNS_P8_BASE64 || !APNS_KEY_ID || !APNS_TEAM_ID || !APNS_BUNDLE_ID || !APNS_ENV)
    return res.status(500).json({ error:"apns_env_missing" });

  const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

  const { data: tokensData, error } = await supabase
    .from("device_tokens")
    .select("token")
    .eq("user_id", recipientId)
    .eq("platform", "ios");

  if (error) return res.status(500).json({ error: "query_device_tokens_failed", detail:error.message });

  const tokens = [...new Set((tokensData||[]).map(r => r.token).filter(Boolean))];
  if (!tokens.length) return res.status(200).json({ success:true, delivered:0, note:"no_device_tokens" });

  const p8Pem = Buffer.from(APNS_P8_BASE64, "base64").toString("utf8");
  const jwt = await makeApnsJwt(p8Pem, APNS_TEAM_ID, APNS_KEY_ID);
  const sandbox = APNS_ENV === "sandbox";

  const payload = {
    aps: {
      alert: { title: senderNickname || "New message", body: message || "" },
      sound: "default",
      "thread-id": conversationId || undefined
    },
    meta: { conversationId, senderId }
  };

  const results = [];
  for (const t of tokens) {
    try {
      const resp = await sendApns({ deviceToken:t, jwt, topic:APNS_BUNDLE_ID, payload, sandbox });
      results.push({ token:t, ok:true, body:resp.body });
    } catch(e) {
      results.push({ token:t, ok:false, error:String(e?.message||e) });
    }
  }
  return res.status(200).json({ success:true, delivered:results.filter(r=>r.ok).length, results });
}
