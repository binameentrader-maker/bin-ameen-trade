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
const SETTINGS_FILE = 'data/settings.json';

const SESSION_SECRET = process.env.PUBLIC_SESSION_SECRET || PASSWORD;

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


/* =========================================================
   PUBLIC WEBSITE PASSWORD SETTINGS (stored in GitHub, same
   pattern as products.json)
========================================================= */

async function getSettingsFile() {
  if (!GITHUB_TOKEN) {
    throw new Error('GITHUB_TOKEN is missing');
  }

  try {
    const result = await githubRequest(
      'GET',
      `/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${SETTINGS_FILE}`
    );

    const content = Buffer
      .from(result.content.replace(/\n/g, ''), 'base64')
      .toString('utf8');

    return {
      sha: result.sha,
      data: JSON.parse(content)
    };

  } catch (error) {

    if (String(error.message).includes('Not Found')) {

      return {
        sha: null,
        data: {
          protectionOn: false,
          passwordHash: null,
          authVersion: 1
        }
      };
    }

    throw error;
  }
}

async function saveSettings(settings) {

  let sha = null;

  try {
    const current = await getSettingsFile();
    sha = current.sha;
  } catch {
    sha = null;
  }

  const content = Buffer
    .from(JSON.stringify(settings, null, 2), 'utf8')
    .toString('base64');

  const body = {
    message: 'Update public website password settings',
    content
  };

  if (sha) {
    body.sha = sha;
  }

  return await githubRequest(
    'PUT',
    `/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${SETTINGS_FILE}`,
    body
  );
}

function hashPassword(pw) {
  return crypto.createHash('sha256').update(String(pw)).digest('hex');
}


/* =========================================================
   SIGNED PUBLIC SESSION TOKENS (httpOnly cookie, 24h expiry,
   invalidated whenever authVersion changes)
========================================================= */

function base64url(input) {
  return Buffer.from(input).toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function base64urlDecode(input) {
  input = input.replace(/-/g, '+').replace(/_/g, '/');
  while (input.length % 4) {
    input += '=';
  }
  return Buffer.from(input, 'base64').toString('utf8');
}

function signToken(payload) {
  const body = base64url(JSON.stringify(payload));
  const sig = crypto
    .createHmac('sha256', SESSION_SECRET)
    .update(body)
    .digest('hex');
  return body + '.' + sig;
}

function verifyToken(token) {

  if (!token || typeof token !== 'string' || !token.includes('.')) {
    return null;
  }

  const [body, sig] = token.split('.');

  const expected = crypto
    .createHmac('sha256', SESSION_SECRET)
    .update(body)
    .digest('hex');

  if (sig !== expected) {
    return null;
  }

  let payload;

  try {
    payload = JSON.parse(base64urlDecode(body));
  } catch {
    return null;
  }

  if (!payload || typeof payload.exp !== 'number' || typeof payload.v !== 'number') {
    return null;
  }

  if (Date.now() > payload.exp) {
    return null;
  }

  return payload;
}

function parseCookies(req) {

  const header = req.headers.cookie;
  const out = {};

  if (!header) {
    return out;
  }

  header.split(';').forEach(pair => {
    const idx = pair.indexOf('=');
    if (idx === -1) return;
    const k = pair.slice(0, idx).trim();
    const v = pair.slice(idx + 1).trim();
    out[k] = decodeURIComponent(v);
  });

  return out;
}

function setPublicCookie(res, token) {

  const parts = [
    `bat_public=${encodeURIComponent(token)}`,
    'HttpOnly',
    'Path=/',
    'Max-Age=86400',
    'SameSite=Lax',
    'Secure'
  ];

  res.setHeader('Set-Cookie', parts.join('; '));
}


/* =========================================================
   PUBLIC GUARD — blocks /api/products when protection is ON
   and there is no valid, up-to-date session
========================================================= */

function publicGuard(req, res, next) {

  getSettingsFile()
    .then(({ data: settings }) => {

      if (!settings.protectionOn) {
        return next();
      }

      const cookies = parseCookies(req);
      const payload = verifyToken(cookies.bat_public);

      if (payload && payload.v === (settings.authVersion || 1)) {
        return next();
      }

      return res.status(401).json({
        error: 'Public authentication required'
      });

    })
    .catch(error => {
      console.error('PUBLIC GUARD ERROR:', error);
      res.status(500).json({
        error: 'Settings check failed',
        details: error.message
      });
    });
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


/* =========================================================
   PUBLIC WEBSITE PASSWORD — customer-facing endpoints
========================================================= */

app.get('/api/public-status', async (req, res) => {

  try {

    const settings = (await getSettingsFile()).data;
    const cookies = parseCookies(req);
    const payload = verifyToken(cookies.bat_public);

    const authenticated =
      !!(payload && payload.v === (settings.authVersion || 1));

    res.json({
      protectionOn: !!settings.protectionOn,
      authenticated: settings.protectionOn ? authenticated : true
    });

  } catch (error) {

    console.error('PUBLIC STATUS ERROR:', error);

    res.status(500).json({
      error: 'Status check failed',
      details: error.message
    });
  }

});

app.post('/api/public-login', async (req, res) => {

  try {

    const settings = (await getSettingsFile()).data;

    if (!settings.protectionOn) {
      return res.json({ ok: true });
    }

    const password = req.body.password || '';

    if (!settings.passwordHash || hashPassword(password) !== settings.passwordHash) {
      return res.status(401).json({
        error: 'Incorrect Password'
      });
    }

    const token = signToken({
      exp: Date.now() + (24 * 60 * 60 * 1000),
      v: settings.authVersion || 1
    });

    setPublicCookie(res, token);

    res.json({ ok: true });

  } catch (error) {

    console.error('PUBLIC LOGIN ERROR:', error);

    res.status(500).json({
      error: 'Login failed',
      details: error.message
    });
  }

});


/* =========================================================
   ADMIN — manage the public website password (requires
   existing admin auth, completely separate from public auth)
========================================================= */

app.get('/api/admin/public-settings', auth, async (req, res) => {

  try {

    const settings = (await getSettingsFile()).data;

    res.json({
      protectionOn: !!settings.protectionOn
    });

  } catch (error) {

    console.error('GET PUBLIC SETTINGS ERROR:', error);

    res.status(500).json({
      error: 'Failed to load settings',
      details: error.message
    });
  }

});

app.post('/api/admin/public-settings/toggle', auth, async (req, res) => {

  try {

    const current = await getSettingsFile();
    const settings = current.data;

    settings.protectionOn = !!req.body.on;
    settings.authVersion = (settings.authVersion || 1) + 1;

    await saveSettings(settings);

    res.json({
      ok: true,
      protectionOn: settings.protectionOn
    });

  } catch (error) {

    console.error('TOGGLE PUBLIC PROTECTION ERROR:', error);

    res.status(500).json({
      error: 'Toggle failed',
      details: error.message
    });
  }

});

app.post('/api/admin/public-settings/change-password', auth, async (req, res) => {

  try {

    const { newPassword, confirmPassword } = req.body;

    if (!newPassword || !confirmPassword) {
      return res.status(400).json({
        error: 'Passwords cannot be empty.'
      });
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).json({
        error: 'Passwords do not match.'
      });
    }

    const current = await getSettingsFile();
    const settings = current.data;

    settings.passwordHash = hashPassword(newPassword);
    settings.authVersion = (settings.authVersion || 1) + 1;

    await saveSettings(settings);

    res.json({ ok: true });

  } catch (error) {

    console.error('CHANGE PUBLIC PASSWORD ERROR:', error);

    res.status(500).json({
      error: 'Password change failed',
      details: error.message
    });
  }

});


app.get('/api/products', publicGuard, async (req, res) => {
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
