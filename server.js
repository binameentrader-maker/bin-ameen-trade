const express = require('express');
const path = require('path');
const crypto = require('crypto');
const https = require('https');

const app = express();
app.use(express.json({ limit: '10mb' }));

const PASSWORD = process.env.ADMIN_PASSWORD || 'CHANGE-ME-1234';
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const GITHUB_OWNER = 'binameentrader-maker';
const GITHUB_REPO = 'bin-ameen-trade';
const GITHUB_FILE = 'data/products.json';
const SETTINGS_FILE = 'data/settings.json';
const DESIGN_FILE = 'data/design.json';
const CAROUSEL_FILE = 'data/carousel.json';
// Public and admin sessions use separate signing keys so rotating the admin key
// does not invalidate existing public-catalogue login cookies. Both keys must be
// consistent across all Vercel instances.
const SESSION_SECRET = process.env.PUBLIC_SESSION_SECRET || PASSWORD;
const ADMIN_SESSION_SECRET = process.env.ADMIN_SESSION_SECRET || SESSION_SECRET;


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
      response.on('data', chunk => { result += chunk; });
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
              parsed.message || `GitHub API error ${response.statusCode}`
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
  return { sha: result.sha, data: JSON.parse(content) };
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
   PUBLIC WEBSITE PASSWORD SETTINGS
   (stored in GitHub, same pattern as products.json)
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
    return { sha: result.sha, data: JSON.parse(content) };
  } catch (error) {
    if (String(error.message).includes('Not Found')) {
      return {
        sha: null,
        data: { protectionOn: false, passwordHash: null, authVersion: 1 }
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
  const body = { message: 'Update public website password settings', content };
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
   SIGNED PUBLIC SESSION TOKENS
   (httpOnly cookie, 24h expiry, invalidated whenever authVersion changes)
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

function signToken(payload, secret = SESSION_SECRET) {
  const body = base64url(JSON.stringify(payload));
  const sig = crypto
    .createHmac('sha256', secret)
    .update(body)
    .digest('hex');
  return body + '.' + sig;
}

function verifyToken(token, secret = SESSION_SECRET) {
  if (!token || typeof token !== 'string' || token.length > 4096 || !token.includes('.')) {
    return null;
  }
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [body, sig] = parts;
  const expected = crypto
    .createHmac('sha256', secret)
    .update(body)
    .digest('hex');
  // Constant-time comparison avoids leaking signature information.
  const suppliedBuffer = Buffer.from(sig || '', 'utf8');
  const expectedBuffer = Buffer.from(expected, 'utf8');
  if (suppliedBuffer.length !== expectedBuffer.length ||
      !crypto.timingSafeEqual(suppliedBuffer, expectedBuffer)) {
    return null;
  }
  let payload;
  try {
    payload = JSON.parse(base64urlDecode(body));
  } catch {
    return null;
  }
  if (!payload || typeof payload.exp !== 'number' || Date.now() > payload.exp) {
    return null;
  }
  return payload;
}

function createAdminToken() {
  return signToken({ role: 'admin', exp: Date.now() + (12 * 60 * 60 * 1000), v: 1 }, ADMIN_SESSION_SECRET);
}

function getBearerToken(req) {
  const header = req.headers.authorization || '';
  const match = /^Bearer\s+(.+)$/i.exec(header);
  return match ? match[1].trim() : '';
}

function isAdminToken(token) {
  const payload = verifyToken(token, ADMIN_SESSION_SECRET);
  return !!(payload && payload.role === 'admin');
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
   PUBLIC GUARD
   Blocks /api/products when protection is ON and there is no
   valid, up-to-date session.
   Admin requests (valid Bearer token from /api/login) are
   always allowed through, regardless of public protection state.
========================================================= */

function publicGuard(req, res, next) {
  // Admin bypass — a logged-in admin should never be blocked by
  // the public website password.
  const adminToken = getBearerToken(req);
  if (adminToken && isAdminToken(adminToken)) {
    return next();
  }

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
      return res.status(401).json({ error: 'Public authentication required' });
    })
    .catch(error => {
      console.error('PUBLIC GUARD ERROR:', error);
      res.status(500).json({ error: 'Settings check failed', details: error.message });
    });
}

function auth(req, res, next) {
  const token = getBearerToken(req);
  if (!isAdminToken(token)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

app.post('/api/login', (req, res) => {
  if (String(req.body.password || '') !== PASSWORD) {
    return res.status(401).json({ error: 'Wrong password' });
  }
  // Stateless signed token works across separate Vercel serverless instances.
  res.set('Cache-Control', 'no-store');
  res.json({ token: createAdminToken(), expiresIn: 12 * 60 * 60 });
});

/* =========================================================
   PUBLIC WEBSITE PASSWORD — customer-facing endpoints
========================================================= */

app.get('/api/public-status', async (req, res) => {
  try {
    const settings = (await getSettingsFile()).data;
    const cookies = parseCookies(req);
    const payload = verifyToken(cookies.bat_public);
    const authenticated = !!(payload && payload.v === (settings.authVersion || 1));
    res.json({
      protectionOn: !!settings.protectionOn,
      authenticated: settings.protectionOn ? authenticated : true
    });
  } catch (error) {
    console.error('PUBLIC STATUS ERROR:', error);
    res.status(500).json({ error: 'Status check failed', details: error.message });
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
      return res.status(401).json({ error: 'Incorrect Password' });
    }
    const token = signToken({
      exp: Date.now() + (24 * 60 * 60 * 1000),
      v: settings.authVersion || 1
    });
    setPublicCookie(res, token);
    res.json({ ok: true });
  } catch (error) {
    console.error('PUBLIC LOGIN ERROR:', error);
    res.status(500).json({ error: 'Login failed', details: error.message });
  }
});

/* =========================================================
   ADMIN — manage the public website password
   (requires existing admin auth, completely separate from public auth)
========================================================= */

app.get('/api/admin/public-settings', auth, async (req, res) => {
  try {
    const settings = (await getSettingsFile()).data;
    res.json({ protectionOn: !!settings.protectionOn });
  } catch (error) {
    console.error('GET PUBLIC SETTINGS ERROR:', error);
    res.status(500).json({ error: 'Failed to load settings', details: error.message });
  }
});

app.post('/api/admin/public-settings/toggle', auth, async (req, res) => {
  try {
    const current = await getSettingsFile();
    const settings = current.data;
    settings.protectionOn = !!req.body.on;
    settings.authVersion = (settings.authVersion || 1) + 1;
    await saveSettings(settings);
    res.json({ ok: true, protectionOn: settings.protectionOn });
  } catch (error) {
    console.error('TOGGLE PUBLIC PROTECTION ERROR:', error);
    res.status(500).json({ error: 'Toggle failed', details: error.message });
  }
});

app.post('/api/admin/public-settings/change-password', auth, async (req, res) => {
  try {
    const { newPassword, confirmPassword } = req.body;
    if (!newPassword || !confirmPassword) {
      return res.status(400).json({ error: 'Passwords cannot be empty.' });
    }
    if (newPassword !== confirmPassword) {
      return res.status(400).json({ error: 'Passwords do not match.' });
    }
    const current = await getSettingsFile();
    const settings = current.data;
    settings.passwordHash = hashPassword(newPassword);
    settings.authVersion = (settings.authVersion || 1) + 1;
    await saveSettings(settings);
    res.json({ ok: true });
  } catch (error) {
    console.error('CHANGE PUBLIC PASSWORD ERROR:', error);
    res.status(500).json({ error: 'Password change failed', details: error.message });
  }
});


/* =========================================================
   CATALOGUE DESIGN SETTINGS
   Draft and published versions are stored in data/design.json.
========================================================= */
const DEFAULT_DESIGN = {
  siteTitle: 'BIN AMEEN',
  pageBg: '#c8d3df',
  headerBg: '#ffffff',
  primaryColor: '#1f293d',
  textColor: '#1f293d',
  cardBg: '#ffffff',
  borderColor: '#8fa0b5',
  borderRadius: 0,
  productImageSize: 92,
  cardPadding: 7,
  desktopContentWidth: 900,
  desktopColumns: 2
};

async function getDesignFile() {
  if (!GITHUB_TOKEN) throw new Error('GITHUB_TOKEN is missing');
  try {
    const result = await githubRequest(
      'GET',
      `/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${DESIGN_FILE}`
    );
    const content = Buffer.from(result.content.replace(/\n/g, ''), 'base64').toString('utf8');
    const parsed = JSON.parse(content);
    return {
      sha: result.sha,
      data: {
        draft: { ...DEFAULT_DESIGN, ...(parsed.draft || parsed.published || {}) },
        published: { ...DEFAULT_DESIGN, ...(parsed.published || {}) }
      }
    };
  } catch (error) {
    if (String(error.message).includes('Not Found')) {
      return { sha: null, data: { draft: { ...DEFAULT_DESIGN }, published: { ...DEFAULT_DESIGN } } };
    }
    throw error;
  }
}

async function saveDesignFile(designData) {
  const current = await getDesignFile();
  const content = Buffer.from(JSON.stringify(designData, null, 2), 'utf8').toString('base64');
  const body = { message: 'Update BIN AMEEN catalogue design', content };
  if (current.sha) body.sha = current.sha;
  return githubRequest(
    'PUT',
    `/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${DESIGN_FILE}`,
    body
  );
}

function cleanDesign(input) {
  const result = { ...DEFAULT_DESIGN };
  const colorKeys = ['pageBg','headerBg','primaryColor','textColor','cardBg','borderColor'];
  colorKeys.forEach(key => {
    if (typeof input[key] === 'string' && /^#[0-9a-fA-F]{6}$/.test(input[key])) result[key] = input[key];
  });
  if (typeof input.siteTitle === 'string') result.siteTitle = input.siteTitle.trim().slice(0, 48) || 'BIN AMEEN';
  if (Number.isFinite(Number(input.borderRadius))) result.borderRadius = Math.max(0, Math.min(24, Number(input.borderRadius)));
  if (Number.isFinite(Number(input.productImageSize))) result.productImageSize = Math.max(56, Math.min(160, Number(input.productImageSize)));
  if (Number.isFinite(Number(input.cardPadding))) result.cardPadding = Math.max(3, Math.min(24, Number(input.cardPadding)));
  if (Number.isFinite(Number(input.desktopContentWidth))) result.desktopContentWidth = Math.max(480, Math.min(1400, Number(input.desktopContentWidth)));
  if (Number.isFinite(Number(input.desktopColumns))) result.desktopColumns = Math.max(1, Math.min(3, Math.round(Number(input.desktopColumns))));
  return result;
}

app.get('/api/design', async (req, res) => {
  try {
    const design = await getDesignFile();
    res.set('Cache-Control', 'no-store');
    res.json({ published: design.data.published });
  } catch (error) {
    console.error('GET PUBLIC DESIGN ERROR:', error);
    res.status(500).json({ error: 'Design load failed', details: error.message });
  }
});

app.get('/api/admin/design', auth, async (req, res) => {
  try {
    const design = await getDesignFile();
    res.json(design.data);
  } catch (error) {
    console.error('GET ADMIN DESIGN ERROR:', error);
    res.status(500).json({ error: 'Design load failed', details: error.message });
  }
});

app.put('/api/admin/design/draft', auth, async (req, res) => {
  try {
    const current = await getDesignFile();
    current.data.draft = cleanDesign(req.body || {});
    await saveDesignFile(current.data);
    res.json({ ok: true, draft: current.data.draft });
  } catch (error) {
    console.error('SAVE DESIGN DRAFT ERROR:', error);
    res.status(500).json({ error: 'Design draft save failed', details: error.message });
  }
});

app.post('/api/admin/design/publish', auth, async (req, res) => {
  try {
    const current = await getDesignFile();
    current.data.published = cleanDesign(current.data.draft || {});
    await saveDesignFile(current.data);
    res.json({ ok: true, published: current.data.published });
  } catch (error) {
    console.error('PUBLISH DESIGN ERROR:', error);
    res.status(500).json({ error: 'Design publish failed', details: error.message });
  }
});


/* =========================================================
   PUBLIC CAROUSEL + ADMIN CAROUSEL MANAGER
   Slide metadata is stored in GitHub data/carousel.json.
   Uploaded banner images are committed under public/uploads/carousel/.
========================================================= */
async function getCarouselFile(){
  if(!GITHUB_TOKEN) throw new Error('GITHUB_TOKEN is missing');
  try{
    const result=await githubRequest('GET',`/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${CAROUSEL_FILE}`);
    const content=Buffer.from(result.content.replace(/\n/g,''),'base64').toString('utf8');
    const parsed=JSON.parse(content);
    return {sha:result.sha,data:{autoplay:parsed.autoplay!==false,interval:[3000,5000,7000,10000].includes(Number(parsed.interval))?Number(parsed.interval):5000,slides:Array.isArray(parsed.slides)?parsed.slides:[]}};
  }catch(error){
    if(String(error.message).includes('Not Found'))return {sha:null,data:{autoplay:true,interval:5000,slides:[]}};
    throw error;
  }
}
async function saveCarouselFile(data){
  const current=await getCarouselFile();
  const clean={autoplay:data.autoplay!==false,interval:[3000,5000,7000,10000].includes(Number(data.interval))?Number(data.interval):5000,slides:(Array.isArray(data.slides)?data.slides:[]).slice(0,30).map((s,i)=>({id:String(s.id||Date.now()+i),title:String(s.title||'').slice(0,100),subtitle:String(s.subtitle||'').slice(0,180),link:String(s.link||'').slice(0,1000),imageUrl:String(s.imageUrl||'').slice(0,1000),order:Number.isFinite(Number(s.order))?Number(s.order):i+1,enabled:s.enabled!==false}))};
  const content=Buffer.from(JSON.stringify(clean,null,2),'utf8').toString('base64');
  const body={message:'Update BIN AMEEN carousel slides',content};if(current.sha)body.sha=current.sha;
  await githubRequest('PUT',`/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${CAROUSEL_FILE}`,body);
  return clean;
}
app.get('/api/carousel',async(req,res)=>{try{const d=(await getCarouselFile()).data;res.set('Cache-Control','no-store');res.json(d);}catch(e){console.error('PUBLIC CAROUSEL ERROR:',e);res.status(500).json({error:'Carousel load failed'});}});
app.get('/api/admin/carousel',auth,async(req,res)=>{try{res.set('Cache-Control','no-store');res.json((await getCarouselFile()).data);}catch(e){console.error('ADMIN CAROUSEL LOAD ERROR:',e);res.status(500).json({error:'Carousel load failed',details:e.message});}});
app.put('/api/admin/carousel',auth,async(req,res)=>{try{const saved=await saveCarouselFile(req.body||{});res.json({ok:true,...saved});}catch(e){console.error('CAROUSEL SAVE ERROR:',e);res.status(500).json({error:'Carousel save failed',details:e.message});}});
app.post('/api/admin/carousel/upload',auth,async(req,res)=>{
  try{
    const {fileName,mimeType,data}=req.body||{};
    if(!/^image\/(png|jpeg|webp)$/.test(String(mimeType||'')))return res.status(400).json({error:'Only PNG, JPG and WEBP images are allowed'});
    if(typeof data!=='string'||data.length<20||data.length>8*1024*1024)return res.status(400).json({error:'Image is missing or larger than 6 MB'});
    const raw=data.replace(/^data:image\/(png|jpeg|webp);base64,/,'');
    if(!/^[A-Za-z0-9+/]+={0,2}$/.test(raw))return res.status(400).json({error:'Invalid image data'});
    const ext=mimeType==='image/jpeg'?'jpg':mimeType.split('/')[1];
    const safe=String(fileName||'banner').replace(/[^a-z0-9_-]/gi,'-').slice(0,35)||'banner';
    const filePath=`public/uploads/carousel/${Date.now()}-${safe}.${ext}`;
    const content=raw.replace(/\s/g,'');
    await githubRequest('PUT',`/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${filePath}`,{message:'Upload BIN AMEEN carousel banner',content});
    res.json({ok:true,imageUrl:'/uploads/carousel/'+filePath.split('/').pop()});
  }catch(e){console.error('CAROUSEL IMAGE UPLOAD ERROR:',e);res.status(500).json({error:'Image upload failed',details:e.message});}
});

app.get('/api/products', publicGuard, async (req, res) => {
  try {
    const result = await getProductsFile();
    res.json(result.data);
  } catch (error) {
    console.error('GET PRODUCTS ERROR:', error);
    res.status(500).json({ error: 'Products load failed', details: error.message });
  }
});

app.post('/api/products', auth, async (req, res) => {
  try {
    const current = await getProductsFile();
    const product = { id: Date.now(), ...req.body };
    const products = [...current.data, product];
    await saveProducts(products);
    res.json(product);
  } catch (error) {
    console.error('ADD PRODUCT ERROR:', error);
    res.status(500).json({ error: 'Product save failed', details: error.message });
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
      return res.status(404).json({ error: 'Product not found' });
    }
    products[index] = { ...products[index], ...req.body, id: products[index].id };
    await saveProducts(products);
    res.json(products[index]);
  } catch (error) {
    console.error('EDIT PRODUCT ERROR:', error);
    res.status(500).json({ error: 'Product update failed', details: error.message });
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
    res.status(500).json({ error: 'Product delete failed', details: error.message });
  }
});

app.use(
  express.static(
    path.join(__dirname, 'public')
  )
);

module.exports = app;
