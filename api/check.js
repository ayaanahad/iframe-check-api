export default async function handler(req, res) {
  const { url } = req.query;

  try {
    const response = await fetch(url, {
      method: "GET",
      redirect: "follow",
    });

    const xfo = (response.headers.get("x-frame-options") || "").toLowerCase();
    const csp = (response.headers.get("content-security-policy") || "").toLowerCase();

    let canEmbed = true;
    let reason = "allowed";

    // 🔴 ONLY strong blocks
    if (xfo.includes("deny")) {
      canEmbed = false;
      reason = "xfo=deny";
    }

    if (xfo.includes("sameorigin")) {
      canEmbed = false;
      reason = "xfo=sameorigin";
    }

    if (csp.includes("frame-ancestors") && csp.includes("'none'")) {
      canEmbed = false;
      reason = "csp=none";
    }

    return res.json({
      success: true,
      canEmbed,
      reason
    });

  } catch (e) {
    return res.json({
      success: false,
      canEmbed: true
    });
  }
}