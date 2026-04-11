import type { NextApiRequest, NextApiResponse } from "next";
import { requireAdmin } from "@/lib/admin";
import { getSetting } from "@/lib/server/site-settings-server";

async function testBark(url: string, title: string, body: string): Promise<string> {
  const res = await fetch(`${url.replace(/\/$/, "")}/${encodeURIComponent(title)}/${encodeURIComponent(body)}`, {
    method: "GET",
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return "Bark 推送成功";
}

async function testTelegram(token: string, chatId: string, text: string): Promise<string> {
  const res = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ chat_id: chatId, text }),
  });
  const data = await res.json();
  if (!data.ok) throw new Error(data.description || "发送失败");
  return "Telegram 推送成功";
}

async function testWebhook(url: string, method: string, payload: object): Promise<string> {
  const res = await fetch(url, {
    method: method || "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return `Webhook 调用成功 (${method || "POST"} ${res.status})`;
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const session = await requireAdmin(req, res);
  if (!session) return;

  const { channel } = req.body as { channel: string };
  const siteName = (await getSetting("site_logo_text")) || process.env.NEXT_PUBLIC_SITE_TITLE || "WHOIS Lookup";
  const testTitle = `${siteName} 通知测试`;
  const testBody = `这是一条来自 ${siteName} 后台的测试通知消息，发送时间: ` + new Date().toLocaleString("zh-CN");

  try {
    let message = "";
    switch (channel) {
      case "bark": {
        const url = await getSetting("notify_bark_url");
        if (!url) throw new Error("未配置 Bark URL");
        message = await testBark(url, testTitle, testBody);
        break;
      }
      case "telegram": {
        const token = await getSetting("notify_telegram_token");
        const chatId = await getSetting("notify_telegram_chat_id");
        if (!token) throw new Error("未配置 Telegram Bot Token");
        if (!chatId) throw new Error("未配置 Telegram Chat ID");
        message = await testTelegram(token, chatId, `*${testTitle}*\n${testBody}`);
        break;
      }
      case "dingding": {
        const webhook = await getSetting("notify_dingding_webhook");
        if (!webhook) throw new Error("未配置钉钉 Webhook");
        message = await testWebhook(webhook, "POST", {
          msgtype: "text",
          text: { content: `${testTitle}\n${testBody}` },
        });
        break;
      }
      case "feishu": {
        const webhook = await getSetting("notify_feishu_webhook");
        if (!webhook) throw new Error("未配置飞书 Webhook");
        message = await testWebhook(webhook, "POST", {
          msg_type: "text",
          content: { text: `${testTitle}\n${testBody}` },
        });
        break;
      }
      case "wecom": {
        const webhook = await getSetting("notify_wecom_webhook");
        if (!webhook) throw new Error("未配置企业微信 Webhook");
        message = await testWebhook(webhook, "POST", {
          msgtype: "text",
          text: { content: `${testTitle}\n${testBody}` },
        });
        break;
      }
      case "generic": {
        const url = await getSetting("notify_generic_webhook");
        const method = (await getSetting("notify_generic_webhook_method")) || "POST";
        if (!url) throw new Error("未配置通用 Webhook URL");
        message = await testWebhook(url, method, {
          title: testTitle,
          body: testBody,
          timestamp: Date.now(),
          source: siteName,
        });
        break;
      }
      default:
        throw new Error("未知渠道: " + channel);
    }
    return res.json({ ok: true, message });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return res.json({ ok: false, message: msg });
  }
}
