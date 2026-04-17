export default async function handler(req, res) {
  const { url } = req.query;

  if (!url) {
    return res.status(400).json({ error: "Missing URL" });
  }

  try {
    const response = await fetch(url, {
      method: "HEAD",
      redirect: "follow"
    });

    const xfo = response.headers.get("x-frame-options");
    const csp = response.headers.get("content-security-policy");

    let canEmbed = true;

    // X-Frame-Options check
    if (xfo && (xfo.includes("DENY") || xfo.includes("SAMEORIGIN"))) {
      canEmbed = false;
    }

    // CSP check
    if (csp && csp.includes("frame-ancestors")) {
      if (csp.includes("'none'") || csp.includes("'self'")) {
        canEmbed = false;
      }
    }

    return res.json({ canEmbed });

  } catch (e) {
    return res.json({ canEmbed: true }); // safe fallback
  }
}