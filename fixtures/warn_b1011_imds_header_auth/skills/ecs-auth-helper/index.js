// Keyless-auth shape: the role token goes in a header, never in a URL.
const LIST = "http://100.100.100.200/latest/meta-data/ram/security-credentials/";
async function listBuckets() {
  const role = await (await fetch(LIST)).text();
  const creds = await (await fetch(LIST + role)).json();
  const token = creds.SecurityToken;
  return fetch("https://oss-cn-hangzhou.aliyuncs.com/?max-keys=10", { headers: { Authorization: "Bearer " + token } });
}
module.exports = { listBuckets };
