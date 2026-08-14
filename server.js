const express = require('express');
const path = require('path');
const crypto = require('crypto');
const https = require('https');

const app = express();

app.use(express.json());

const PASSWORD = process.env.ADMIN_PASSWORD || 'CHANGE-ME-1234';
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;

const GITHUB_OWNER = 'binameentrader-maker';
const GITHUB_REPO = 'bin-ameen-trade';
const GITHUB_FILE = 'data/products.json';

const sessions = new Set();

function githubRequest(method, apiPath, body = null) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;

    const options = {
      hostname: 'api.github.com',
      path: apiPath,
      method,
      headers: {
        'User-Agent': 'bin-ameen-trader',
        'Accept': 'application/vnd.github+json',
        'Authorization': `Bearer ${GITHUB_TOKEN}`,
        'X-GitHub-Api-Version': '2022-11-28'
      }
    };

    if (data) {
      options.headers['Content-Type'] = 'application/json';
      options.headers['Content-Length'] = Buffer.byteLength(data);
    }

    const request = https.request(options, response => {
      let result = '';

      response.on('data', chunk => {
        result += chunk;
      });

      response.on('end', () => {
        let parsed = {};

        try {
          parsed = result ? JSON.parse(result) : {};
        } catch {
          parsed = {};
        }

        if (response.statusCode >= 200 && response.statusCode < 300) {
          resolve(parsed);
        } else {
          reject(
            new Error(
              parsed.message ||
              `GitHub API error ${response.statusCode}`
            )
          );
        }
      });
    });

    request.on('error', reject);

    if (data) {
      request.write(data);
    }

    request.end();
  });
}

async function getProductsFile() {
  if (!GITHUB_TOKEN) {
    throw new Error('GITHUB_TOKEN is missing');
  }

  const result = await githubRequest(
    'GET',
    `/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${GITHUB_FILE}`
  );

  const content = Buffer
    .from(result.content.replace(/\n/g, ''), 'base64')
    .toString('utf8');

  return {
    sha: result.sha,
    data: JSON.parse(content)
  };
}

async function saveProducts(products) {
  const current = await getProductsFile();

  const content = Buffer
    .from(JSON.stringify(products, null, 2), 'utf8')
    .toString('base64');

  return await githubRequest(
    'PUT',
    `/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${GITHUB_FILE}`,
    {
      message: 'Update products from Admin Panel',
      content,
      sha: current.sha
    }
  );
}

function auth(req, res, next) {
  const token =
    (req.headers.authorization || '').replace('Bearer ', '');

  if (!sessions.has(token)) {
    return res.status(401).json({
      error: 'Unauthorized'
    });
  }

  next();
}

app.post('/api/login', (req, res) => {
  if (req.body.password !== PASSWORD) {
    return res.status(401).json({
      error: 'Wrong password'
    });
  }

  const token = crypto.randomBytes(24).toString('hex');

  sessions.add(token);

  res.json({ token });
});

app.get('/api/products', async (req, res) => {
  try {
    const result = await getProductsFile();
    res.json(result.data);
  } catch (error) {
    console.error('GET PRODUCTS ERROR:', error);

    res.status(500).json({
      error: 'Products load failed',
      details: error.message
    });
  }
});

app.post('/api/products', auth, async (req, res) => {
  try {
    const current = await getProductsFile();

    const product = {
      id: Date.now(),
      ...req.body
    };

    const products = [...current.data, product];

    await saveProducts(products);

    res.json(product);
  } catch (error) {
    console.error('ADD PRODUCT ERROR:', error);

    res.status(500).json({
      error: 'Product save failed',
      details: error.message
    });
  }
});

app.put('/api/products/:id', auth, async (req, res) => {
  try {
    const current = await getProductsFile();

    const products = current.data;

    const index = products.findIndex(
      x => String(x.id) === String(req.params.id)
    );

    if (index < 0) {
      return res.status(404).json({
        error: 'Product not found'
      });
    }

    products[index] = {
      ...products[index],
      ...req.body,
      id: products[index].id
    };

    await saveProducts(products);

    res.json(products[index]);
  } catch (error) {
    console.error('EDIT PRODUCT ERROR:', error);

    res.status(500).json({
      error: 'Product update failed',
      details: error.message
    });
  }
});

app.delete('/api/products/:id', auth, async (req, res) => {
  try {
    const current = await getProductsFile();

    const products = current.data.filter(
      x => String(x.id) !== String(req.params.id)
    );

    await saveProducts(products);

    res.status(204).end();
  } catch (error) {
    console.error('DELETE PRODUCT ERROR:', error);

    res.status(500).json({
      error: 'Product delete failed',
      details: error.message
    });
  }
});

app.use(
  express.static(
    path.join(__dirname, 'public')
  )
);

module.exports = app;
