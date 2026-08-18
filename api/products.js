const https = require("https");

const GITHUB_TOKEN = process.env.GITHUB_TOKEN;

const OWNER = "binameentrader-maker";
const REPO = "bin-ameen-trade";
const FILE = "data/products.json";

function githubRequest() {
  return new Promise((resolve, reject) => {

    if (!GITHUB_TOKEN) {
      reject(new Error("GITHUB_TOKEN is missing"));
      return;
    }

    const options = {
      hostname: "api.github.com",
      path: `/repos/${OWNER}/${REPO}/contents/${FILE}`,
      method: "GET",
      headers: {
        "User-Agent": "bin-ameen-trader",
        "Accept": "application/vnd.github+json",
        "Authorization": `Bearer ${GITHUB_TOKEN}`,
        "X-GitHub-Api-Version": "2022-11-28"
      }
    };

    const req = https.request(options, response => {

      let body = "";

      response.on("data", chunk => {
        body += chunk;
      });

      response.on("end", () => {

        let data;

        try {
          data = JSON.parse(body);
        } catch {
          reject(new Error("GitHub returned invalid response"));
          return;
        }

        if (response.statusCode < 200 || response.statusCode >= 300) {
          reject(
            new Error(
              data.message ||
              `GitHub error ${response.statusCode}`
            )
          );
          return;
        }

        try {

          const decoded = Buffer
            .from(data.content.replace(/\n/g, ""), "base64")
            .toString("utf8");

          const products = JSON.parse(decoded);

          resolve(products);

        } catch (error) {
          reject(
            new Error(
              "products.json is invalid: " + error.message
            )
          );
        }

      });

    });

    req.on("error", reject);

    req.end();

  });
}

module.exports = async function handler(req, res) {

  try {

    const products = await githubRequest();

    res.status(200).json(products);

  } catch (error) {

    console.error("PRODUCT API ERROR:", error);

    res.status(500).json({
      error: "Products load failed",
      details: error.message
    });

  }

};
