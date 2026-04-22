export default async function handler(req, res) {
  const { url } = req.query;

  // 1) Validate input
  if (!url) {
    return res.status(400).json({
      success: false,
      error: "Missing URL"
    });
  }

  let target;
  try {
    target = new URL(url);
  } catch {
    return res.status(400).json({
      success: false,
      error: "Invalid URL"
    });
  }

  try {
    // 2) Timeout protection (important for Vercel)
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 7000);

    const response = await fetch(target.toString(), {
      method: "GET",
      redirect: "follow",
      signal: controller.signal,
      headers: {
        "User-Agent": "Mozilla/5.0 (Phototul Embed Checker)"
      }
    });

    clearTimeout(timeout);

    const finalUrl = response.url;

    // 3) Read headers (lowercased for consistency)
    const xfo = (response.headers.get("x-frame-options") || "").toLowerCase();
    const csp = (response.headers.get("content-security-policy") || "").toLowerCase();

    let canEmbed = true;
    let reason = "allowed";

    // 4) HARD BLOCK RULES ONLY (no guesswork)

    // X-Frame-Options
    if (xfo.includes("deny")) {
      canEmbed = false;
      reason = "xfo=deny";
    }

    if (xfo.includes("sameorigin")) {
      canEmbed = false;
      reason = "xfo=sameorigin";
    }

    // CSP frame-ancestors
    if (csp.includes("frame-ancestors") && csp.includes("'none'")) {
      canEmbed = false;
      reason = "csp=none";
    }

    // 5) Response
    return res.status(200).json({
      success: true,
      canEmbed,
      reason,
      finalUrl,
      headers: {
        xFrameOptions: xfo || null,
        contentSecurityPolicy: csp || null
      }
    });

  } catch (err) {
    // Safe fallback (don’t block UI on network errors)
    return res.status(200).json({
      success: false,
      canEmbed: true,
      reason: "request_failed",
      error: err.message
    });
  }
}