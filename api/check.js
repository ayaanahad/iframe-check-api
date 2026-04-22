export default async function handler(req, res) {
  const { url } = req.query;

  if (!url) {
    return res.status(400).json({
      success: false,
      error: "Missing URL"
    });
  }

  try {
    // Validate URL
    let target;
    try {
      target = new URL(url);
    } catch {
      return res.status(400).json({
        success: false,
        error: "Invalid URL"
      });
    }

    // Use GET (not HEAD) for accurate headers after redirects
    const response = await fetch(target.toString(), {
      method: "GET",
      redirect: "follow",
      headers: {
        "User-Agent": "Mozilla/5.0 (Phototul Embed Checker)"
      }
    });

    const finalUrl = response.url;

    const xfo = response.headers.get("x-frame-options") || "";
    const csp = response.headers.get("content-security-policy") || "";

    const xfoVal = xfo.toLowerCase();
    const cspVal = csp.toLowerCase();

    let canEmbed = true;
    let confidence = "high"; // high | medium | low
    let reason = "allowed";

    // 🔴 Strong block signals
    if (xfoVal.includes("deny")) {
      canEmbed = false;
      reason = "xfo=deny";
      confidence = "high";
    }

    if (cspVal.includes("frame-ancestors") && cspVal.includes("'none'")) {
      canEmbed = false;
      reason = "csp=none";
      confidence = "high";
    }

    // ⚠️ Weak / unreliable signals
    else if (xfoVal.includes("sameorigin")) {
      // Do NOT hard block — many sites still work
      canEmbed = true;
      reason = "xfo=sameorigin";
      confidence = "low";
    }

    else if (cspVal.includes("frame-ancestors")) {
      // Restricted but unknown (domain-specific rules)
      canEmbed = false;
      reason = "csp=restricted";
      confidence = "medium";
    }

    return res.status(200).json({
      success: true,
      canEmbed,
      confidence,
      reason,
      headers: {
        xFrameOptions: xfo || null,
        contentSecurityPolicy: csp || null
      },
      finalUrl
    });

  } catch (err) {
    return res.status(200).json({
      success: false,
      canEmbed: false,
      confidence: "low",
      reason: "request_failed",
      error: err.message
    });
  }
}