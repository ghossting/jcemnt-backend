const express = require('express');
const path = require('path');
const { randomUUID } = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');
require('dotenv').config({ path: path.join(__dirname, '.env') });

const { runAsync, getAsync, allAsync } = require('../db');
const { validarSenhaParaLogin } = require('./utils/auth-password');

const app = express();
const PORT = Number(process.env.PORT) || 10000;
const JWT_SECRET = process.env.JWT_SECRET;
const WRITER_SECRET = process.env.WRITER_SECRET;
const ADMIN_SECRET = process.env.ADMIN_SECRET;
const EMAIL_FROM = process.env.EMAIL_FROM || 'no-reply@cemtn.local';
const SMTP_HOST = process.env.SMTP_HOST;
const SMTP_PORT = process.env.SMTP_PORT ? Number(process.env.SMTP_PORT) : 587;
const SMTP_SECURE = process.env.SMTP_SECURE === 'true';
const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASS = process.env.SMTP_PASS;

let mailTransport = null;
if (SMTP_HOST && SMTP_PORT) {
  mailTransport = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_SECURE,
    auth: SMTP_USER && SMTP_PASS ? { user: SMTP_USER, pass: SMTP_PASS } : undefined,
  });
}

async function sendVerificationEmail(email, code) {
  const subject = 'Código de verificação - Jornal Cemtn';
  const text = `Seu código de verificação é: ${code}\n\nUse-o em até 10 minutos.`;

  if (mailTransport) {
    await mailTransport.sendMail({
      from: EMAIL_FROM,
      to: email,
      subject,
      text,
    });
    return;
  }

  console.log(`VERIFICATION EMAIL: ${email} - código: ${code}`);
}

const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN;
const allowedOrigins = (ALLOWED_ORIGIN || 'http://localhost:3000')
  .split(',')
  .map((value) => value.trim())
  .filter(Boolean);

function isAllowedOrigin(origin) {
  if (!origin) return true;
  if (allowedOrigins.includes(origin)) return true;

  const normalizedOrigin = origin.toLowerCase();
  return normalizedOrigin.startsWith('http://localhost') ||
    normalizedOrigin.startsWith('http://127.0.0.1') ||
    normalizedOrigin.startsWith('https://localhost') ||
    normalizedOrigin.startsWith('https://127.0.0.1') ||
    normalizedOrigin.endsWith('.netlify.app') ||
    normalizedOrigin.endsWith('.vercel.app') ||
    normalizedOrigin.endsWith('.github.dev');
}

if (!JWT_SECRET) {
  console.error('ERRO: JWT_SECRET não definido no .env');
  process.exit(1);
}

if (!WRITER_SECRET || !ADMIN_SECRET) {
  console.error('ERRO: WRITER_SECRET e ADMIN_SECRET devem ser definidos no .env');
  process.exit(1);
}

app.use(express.json({ limit: '50kb' }));  
app.use(express.urlencoded({ extended: true, limit: '50kb' }));

app.use(cors({
  origin: (origin, callback) => {
    if (isAllowedOrigin(origin)) {
      callback(null, true);
      return;
    }

    callback(null, false);
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}));

const CLIENT_DIR = path.join(__dirname, '..');
const PUBLIC_IMG_DIR = path.join(CLIENT_DIR, 'img');
app.use('/img', express.static(PUBLIC_IMG_DIR, { dotfiles: 'deny', index: false, fallthrough: false }));
app.use((req, res, next) => {
  if (req.path.includes('..')) {
    return res.status(400).end();
  }

  const blockedPaths = [
    '.env',
    'jornal.db',
    'db.js',
    'server.js',
    'package.json',
    'package-lock.json',
    '.git',
  ];

  if (blockedPaths.some((name) => req.path.includes(name) || req.path.startsWith(`/${name}`))) {
    return res.status(404).end();
  }

  next();
});



function autenticarToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ erro: "Acesso negado. Token não fornecido." });

  if (tokenBlacklist.has(token)) {
    return res.status(401).json({ erro: "Token inválido. Faça login novamente." });
  }

  jwt.verify(token, JWT_SECRET, (err, usuario) => {
    if (err) return res.status(403).json({ erro: "Token inválido ou expirado." });
    req.usuario = usuario;
    next();
  });
}

function permitirApenas(funcoesPermitidas) {
  return (req, res, next) => {
    if (!req.usuario || !funcoesPermitidas.includes(req.usuario.role)) {
      return res.status(403).json({ erro: "Bloqueado: Você não tem permissão." });
    }
    if (req.usuario.status === 'pendente') {
      return res.status(403).json({ erro: "Sua conta aguarda aprovação do admin." });
    }
    next();
  };
}

const tokenBlacklist = new Set();


setInterval(() => {
  const agora = Math.floor(Date.now() / 1000);
  for (const token of tokenBlacklist) {
    try {
      jwt.verify(token, JWT_SECRET);
    } catch (err) {
  
      tokenBlacklist.delete(token);
    }
  }
}, 60 * 60 * 1000);
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 10,
  message: { message: 'Muitas tentativas de login. Tente novamente em 15 minutos.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const cadastroLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hora
  max: 5,
  message: { erro: 'Muitas solicitações de cadastro. Tente novamente em 1 hora.' },
  standardHeaders: true,
  legacyHeaders: false,
});

function validarTexto(valor, nomeCampo, maxLen = 500) {
  if (!valor || typeof valor !== 'string') return `${nomeCampo} é obrigatório.`;
  if (valor.trim().length === 0) return `${nomeCampo} não pode ser vazio.`;
  if (valor.trim().length > maxLen) return `${nomeCampo} excede o limite de ${maxLen} caracteres.`;
  return null;
}

function validarRating(valor) {
  if (typeof valor !== 'number' && typeof valor !== 'string') return 'Avaliação inválida.';
  const n = Number(valor);
  if (!Number.isInteger(n) || n < 1 || n > 5) return 'A avaliação deve ser entre 1 e 5 estrelas.';
  return null;
}

function gerarSlug(texto) {
  return texto.trim().toLowerCase()
    .replace(/\s+/g, '-')
    .replace(/[^a-z0-9-_]/g, '')
    .replace(/--+/g, '-')
    .replace(/^-|-$/g, '');
}



app.get(['/', '/noticias'], (req, res) => {
  res.sendFile(path.join(CLIENT_DIR, 'index.html'));
});




app.post('/auth/request-code', cadastroLimiter, async (req, res, next) => {
  try {
    const { email } = req.body;
    if (!email || typeof email !== 'string' || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
      return res.status(400).json({ message: 'Email inválido.' });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + 10 * 60 * 1000;

    await runAsync(
      `INSERT INTO email_verifications (email, code, "expiresAt", used)
       VALUES ($1, $2, $3, 0)
       ON CONFLICT (email) DO UPDATE SET code = $2, "expiresAt" = $3, used = 0`,
      [normalizedEmail, code, expiresAt]
    );

    await sendVerificationEmail(normalizedEmail, code);
    res.json({ success: true, message: 'Código de verificação enviado para o email.' });
  } catch (error) {
    next(error);
  }
});

app.post('/auth/verify-code', cadastroLimiter, async (req, res, next) => {
  try {
    const { email, code, password, name } = req.body;
    if (!email || !code || !password) {
      return res.status(400).json({ message: 'Email, código e senha são obrigatórios.' });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const verification = await getAsync('SELECT * FROM email_verifications WHERE email = $1', [normalizedEmail]);
    if (!verification || verification.used || verification.code !== String(code).trim() || verification.expiresAt < Date.now()) {
      return res.status(401).json({ message: 'Código inválido ou expirado.' });
    }

    const existingUser = await getAsync('SELECT id FROM users WHERE email = $1', [normalizedEmail]);
    if (existingUser) {
      return res.status(400).json({ message: 'Email já registrado. Faça login.' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const id = randomUUID();
    await runAsync(
      `INSERT INTO users (id, email, password, name, role, status, "createdAt")
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [id, normalizedEmail, passwordHash, name?.trim() || normalizedEmail, 'reader', 'ativo', new Date().toISOString()]
    );

    await runAsync('UPDATE email_verifications SET used = 1 WHERE email = $1', [normalizedEmail]);
    res.json({ success: true, message: 'Email verificado. Senha criada com sucesso.' });
  } catch (error) {
    next(error);
  }
});

app.post('/auth/login', loginLimiter, async (req, res, next) => {
  try {
    const { email, password, accessType = 'reader', secret } = req.body;
    if (!email) {
      return res.status(400).json({ message: 'Email é obrigatório.' });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const user = await getAsync('SELECT * FROM users WHERE email = $1', [normalizedEmail]);
    if (!user) return res.status(401).json({ message: 'Credenciais inválidas.' });

    if (accessType !== 'reader') {
      if (!password) {
        return res.status(400).json({ message: 'Senha é obrigatória para este tipo de acesso.' });
      }
      const senhaValida = await validarSenhaParaLogin(password, user.password, accessType);
      if (!senhaValida) return res.status(401).json({ message: 'Credenciais inválidas.' });
    }

    if (user.status === 'bloqueado') {
      return res.status(403).json({ message: 'Conta bloqueada. Fale com o admin.' });
    }

    if (user.status === 'pendente') {
      return res.status(403).json({ message: 'Conta ainda não aprovada. Aguarde o admin.' });
    }

    let role = 'reader';
    if (accessType === 'writer') {
      if (secret !== WRITER_SECRET) {
        return res.status(401).json({ message: 'tokeninvalido' });
      }
      role = 'writer';
    }
    if (accessType === 'admin') {
      if (secret !== ADMIN_SECRET) {
        return res.status(401).json({ message: 'tokeninvalido' });
      }
      role = 'admin';
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, name: user.name, role, status: user.status },
      JWT_SECRET,
      { expiresIn: '2h' }
    );

    res.json({
      success: true,
      user: { name: user.name, role, status: user.status },
      token,
    });
  } catch (error) {
    next(error);
  }
});

app.put('/admin/users/:email/password', autenticarToken, permitirApenas(['admin']), async (req, res, next) => {
  try {
    const { password } = req.body;
    const email = req.params.email.trim().toLowerCase();
    if (!password) {
      return res.status(400).json({ message: 'Senha é obrigatória.' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const result = await runAsync('UPDATE users SET password = $1 WHERE email = $2', [passwordHash, email]);
    if (result.changes === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado.' });
    }

    res.json({ message: 'Senha atualizada com sucesso.' });
  } catch (error) {
    next(error);
  }
});

app.post('/auth/logout', autenticarToken, (req, res) => {
  const token = req.headers['authorization'].split(' ')[1];
  tokenBlacklist.add(token);
  res.json({ mensagem: 'Logout realizado com sucesso.' });
});

app.get('/admin/pendentes', autenticarToken, permitirApenas(['admin']), async (req, res, next) => {
  try {
    const pendentes = await allAsync("SELECT id, name, username, turma FROM users WHERE status = 'pendente'");
    res.json(pendentes);
  } catch (error) {
    next(error);
  }
});

app.put('/admin/aprovar/:id', autenticarToken, permitirApenas(['admin']), async (req, res, next) => {
  try {
    const { id } = req.params;
    const resultado = await runAsync(
      "UPDATE users SET status = 'ativo', role = 'writer' WHERE id = $1 AND status = 'pendente'",
      [id]
    );

    if (resultado.changes === 0) {
      return res.status(404).json({ erro: 'Usuário não encontrado ou já aprovado.' });
    }
    res.json({ mensagem: 'Usuário aprovado como escritor!' });
  } catch (error) {
    next(error);
  }
});

app.put('/admin/rejeitar/:id', autenticarToken, permitirApenas(['admin']), async (req, res, next) => {
  try {
    const { id } = req.params;
    const resultado = await runAsync(
      "UPDATE users SET status = 'bloqueado' WHERE id = $1 AND status = 'pendente'",
      [id]
    );

    if (resultado.changes === 0) {
      return res.status(404).json({ erro: 'Usuário não encontrado ou já processado.' });
    }
    res.json({ mensagem: 'Usuário rejeitado e bloqueado.' });
  } catch (error) {
    next(error);
  }
});


app.get('/api/categories', async (req, res, next) => {
  try {
    const categories = await allAsync('SELECT id, name, slug FROM categories ORDER BY name ASC');
    res.json(categories);
  } catch (error) {
    next(error);
  }
});

app.post('/api/categories', autenticarToken, permitirApenas(['admin']), async (req, res, next) => {
  try {
    const { name } = req.body;
    const erroName = validarTexto(name, 'Nome da categoria', 100);
    if (erroName) return res.status(400).json({ error: erroName });

    const slug = gerarSlug(name);
    const existing = await getAsync('SELECT id FROM categories WHERE slug = $1', [slug]);
    if (existing) return res.status(400).json({ error: 'Categoria já existe.' });

    const id = randomUUID();
    const createdAt = new Date().toISOString();
    await runAsync('INSERT INTO categories (id, name, slug, "createdAt") VALUES ($1, $2, $3, $4)', [id, name.trim(), slug, createdAt]);
    res.status(201).json({ id, name: name.trim(), slug });
  } catch (error) {
    next(error);
  }
});

app.delete('/api/categories/:id', autenticarToken, permitirApenas(['admin']), async (req, res, next) => {
  try {
    await runAsync('DELETE FROM categories WHERE id = $1', [req.params.id]);
    res.json({ message: 'Categoria deletada.' });
  } catch (error) {
    next(error);
  }
});

app.get('/api/posts', async (req, res, next) => {
  try {
    const posts = await allAsync('SELECT id, title, category, content, videoLink, createdAt, autor, autor_turma, autor_id FROM posts ORDER BY createdAt DESC');
    res.json(posts);
  } catch (error) {
    next(error);
  }
});

app.get('/api/posts/:id', async (req, res, next) => {
  try {
    const post = await getAsync('SELECT * FROM posts WHERE id = $1', [req.params.id]);
    if (!post) return res.status(404).json({ error: 'Publicação não encontrada.' });
    res.json(post);
  } catch (error) {
    next(error);
  }
});

app.post('/api/posts', autenticarToken, permitirApenas(['admin', 'writer']), async (req, res, next) => {
  try {
    const { title, category, content, videoLink, authorName, authorTurma } = req.body;


    const erroTitle = validarTexto(title, 'Título', 200);
    const erroCategory = validarTexto(category, 'Categoria', 100);
    const erroContent = validarTexto(content, 'Conteúdo', 20000);
    const erroAuthor = validarTexto(authorName, 'Nome do autor', 200);
    const erroTurma = validarTexto(authorTurma, 'Turma', 100);
    if (erroTitle || erroCategory || erroContent || erroAuthor || erroTurma) {
      return res.status(400).json({ error: erroTitle || erroCategory || erroContent || erroAuthor || erroTurma });
    }

    const id = randomUUID();
    const createdAt = new Date().toISOString();

    await runAsync(
      `INSERT INTO posts (id, title, category, content, "videoLink", "createdAt", autor, autor_id, autor_turma)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [id, title.trim(), category.trim(), content.trim(), videoLink?.trim().slice(0, 500) || '', createdAt, authorName.trim(), req.usuario.id, authorTurma.trim()]
    );

    const newPost = await getAsync('SELECT * FROM posts WHERE id = $1', [id]);
    res.status(201).json(newPost);
  } catch (error) {
    next(error);
  }
});

app.put('/api/posts/:id', autenticarToken, permitirApenas(['admin', 'writer']), async (req, res, next) => {
  try {
    const { id } = req.params;
    const { title, category, content, videoLink } = req.body;

    const erroTitle = validarTexto(title, 'Título', 200);
    const erroCategory = validarTexto(category, 'Categoria', 100);
    const erroContent = validarTexto(content, 'Conteúdo', 20000);
    if (erroTitle || erroCategory || erroContent) {
      return res.status(400).json({ error: erroTitle || erroCategory || erroContent });
    }

    const post = await getAsync('SELECT * FROM posts WHERE id = $1', [id]);
    if (!post) return res.status(404).json({ error: 'Publicação não encontrada.' });

  
    if (req.usuario.role === 'writer' && post.autor_id !== req.usuario.id) {
      return res.status(403).json({ error: 'Você só pode editar suas próprias publicações.' });
    }

    await runAsync(
      `UPDATE posts SET title = $1, category = $2, content = $3, "videoLink" = $4 WHERE id = $5`,
      [title.trim(), category.trim(), content.trim(), videoLink?.trim().slice(0, 500) || '', id]
    );

    const updatedPost = await getAsync('SELECT * FROM posts WHERE id = $1', [id]);
    res.json(updatedPost);
  } catch (error) {
    next(error);
  }
});

app.delete('/api/posts/:id', autenticarToken, permitirApenas(['admin', 'writer']), async (req, res, next) => {
  try {
    const { id } = req.params;

    const post = await getAsync('SELECT * FROM posts WHERE id = $1', [id]);
    if (!post) return res.status(404).json({ error: 'Publicação não encontrada.' });

    
    if (req.usuario.role === 'writer' && post.autor_id !== req.usuario.id) {
      return res.status(403).json({ error: 'Você só pode deletar suas próprias publicações.' });
    }

    await runAsync('DELETE FROM posts WHERE id = $1', [id]);
    res.json({ mensagem: 'Publicação deletada com sucesso.' });
  } catch (error) {
    next(error);
  }
});

app.get('/api/reclamacoes', async (req, res, next) => {
  try {
    const reclamacoes = await allAsync(
      'SELECT id, username, profilePhoto, content, rating, createdAt FROM complaints ORDER BY createdAt DESC'
    );
    res.json(reclamacoes.map(item => ({
      ...item,
      username: item.username || 'Anônimo',
      profilePhoto: item.profilePhoto || '',
    })));
  } catch (error) {
    next(error);
  }
});

app.post('/api/reclamacoes', async (req, res, next) => {
  try {
    const { username, turma, profilePhoto, content, rating } = req.body;
    const erroTurma = validarTexto(turma, 'Turma', 50);
    const erroContent = validarTexto(content, 'Comentário', 1000);
    const erroRating = validarRating(rating);
    if (erroTurma || erroContent || erroRating) {
      return res.status(400).json({ error: erroTurma || erroContent || erroRating });
    }

    const id = randomUUID();
    const createdAt = new Date().toISOString();
    await runAsync(
      'INSERT INTO complaints (id, username, turma, "profilePhoto", rating, content, "createdAt") VALUES ($1, $2, $3, $4, $5, $6, $7)',
      [id, username?.trim() || '', turma.trim(), profilePhoto?.trim() || '', Number(rating), content.trim(), createdAt]
    );
    res.status(201).json({ message: 'Reclamação registrada com sucesso.' });
  } catch (error) {
    next(error);
  }
});

app.delete('/api/reclamacoes/:id', autenticarToken, permitirApenas(['admin']), async (req, res, next) => {
  try {
    await runAsync('DELETE FROM complaints WHERE id = $1', [req.params.id]);
    res.json({ message: 'Reclamação removida.' });
  } catch (error) {
    next(error);
  }
});

app.get('/api/events', async (req, res, next) => {
  try {
    const events = await allAsync('SELECT * FROM events ORDER BY date ASC');
    res.json(events);
  } catch (error) {
    next(error);
  }
});

app.get('/api/credits', async (req, res, next) => {
  try {
    const credit = await getAsync('SELECT * FROM credits LIMIT 1');
    if (!credit) return res.json({ description: '', authors: [] });

    let authors = [];
    try {
      authors = credit.authors ? JSON.parse(credit.authors) : [];
    } catch (e) {
      authors = [];
    }

    res.json({ description: credit.description, authors });
  } catch (error) {
    next(error);
  }
});


app.use((req, res) => {
  if (req.method === 'GET' && !req.path.startsWith('/api') && !req.path.startsWith('/auth') && !req.path.startsWith('/admin')) {
    return res.sendFile(path.join(CLIENT_DIR, 'index.html'));
  }
  res.status(404).json({ error: 'Rota não encontrada.' });
});

app.use((error, req, res, next) => {
  console.error(error);
  res.status(500).json({ error: 'Erro interno no servidor.' });
});

app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});