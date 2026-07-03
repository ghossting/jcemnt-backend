const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('render.com') ? { rejectUnauthorized: false } : false,
});

pool.on('error', (err) => {
  console.error('Erro inesperado no pool do PostgreSQL:', err);
});

pool.on('connect', () => {
  console.log('Conectado ao banco de dados PostgreSQL.');
});

// Inicializar banco de dados na primeira conexão
initializeDatabase().catch(err => {
  console.error('Erro ao inicializar banco:', err);
  process.exit(1);
});

async function initializeDatabase() {
  const client = await pool.connect();
  try {
    // Tabela de Posts
    await client.query(`
      CREATE TABLE IF NOT EXISTS posts (
        id VARCHAR(255) PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        category VARCHAR(100) NOT NULL,
        content TEXT NOT NULL,
        "videoLink" VARCHAR(500),
        "createdAt" TIMESTAMP NOT NULL,
        autor VARCHAR(255),
        autor_id VARCHAR(255),
        autor_turma VARCHAR(100)
      )
    `);

    // Tabela de Eventos
    await client.query(`
      CREATE TABLE IF NOT EXISTS events (
        id VARCHAR(255) PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        date VARCHAR(50) NOT NULL,
        description TEXT
      )
    `);

    // Tabela de Usuários
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id VARCHAR(255) PRIMARY KEY,
        username VARCHAR(255) UNIQUE,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        name VARCHAR(255) NOT NULL,
        role VARCHAR(50) NOT NULL,
        status VARCHAR(50) NOT NULL,
        turma VARCHAR(100),
        "createdAt" TIMESTAMP NOT NULL
      )
    `);

    // Tabela de Verificações por email
    await client.query(`
      CREATE TABLE IF NOT EXISTS email_verifications (
        email VARCHAR(255) PRIMARY KEY,
        code VARCHAR(255) NOT NULL,
        "expiresAt" BIGINT NOT NULL,
        used SMALLINT NOT NULL DEFAULT 0
      )
    `);

    // Tabela de Créditos
    await client.query(`
      CREATE TABLE IF NOT EXISTS credits (
        id VARCHAR(255) PRIMARY KEY,
        description TEXT,
        authors TEXT
      )
    `);

    // Tabela de Categorias
    await client.query(`
      CREATE TABLE IF NOT EXISTS categories (
        id VARCHAR(255) PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        slug VARCHAR(255) UNIQUE NOT NULL,
        "createdAt" TIMESTAMP NOT NULL
      )
    `);

    // Tabela de Reclamações anônimas
    await client.query(`
      CREATE TABLE IF NOT EXISTS complaints (
        id VARCHAR(255) PRIMARY KEY,
        username VARCHAR(255),
        turma VARCHAR(100) NOT NULL,
        "profilePhoto" VARCHAR(500),
        rating SMALLINT NOT NULL,
        content TEXT NOT NULL,
        "createdAt" TIMESTAMP NOT NULL
      )
    `);

    // Verificar se há dados iniciais
    const result = await client.query('SELECT COUNT(*) as count FROM posts');
    if (result.rows[0].count === 0) {
      await insertInitialData(client);
    }

    console.log('Banco de dados inicializado com sucesso.');
  } catch (err) {
    console.error('Erro ao inicializar banco de dados:', err);
    throw err;
  } finally {
    client.release();
  }
}

async function insertInitialData(client) {
  const { randomUUID } = require('crypto');
  const now = new Date().toISOString();

  // Post inicial
  await client.query(
    `INSERT INTO posts (id, title, category, content, "videoLink", "createdAt") 
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [
      'post-1',
      'Título da Notícia',
      'Últimas Notícias',
      'Espaço destinado para publicação de notícias do jornal eletrônico. textos completos, reportagens e matérias.',
      '',
      now,
    ]
  );

  // Eventos iniciais
  const events = [
    { id: 'event-1', title: 'Olimcemtn', date: '2026-06-20', description: 'Competição esportiva CEMTN.' },
    { id: 'event-2', title: 'Sarau', date: '2026-06-28', description: 'Teatro das turmas' },
    { id: 'event-3', title: 'Coral', date: '2026-07-05', description: 'Apresentação do coral' },
  ];

  for (const event of events) {
    await client.query(
      `INSERT INTO events (id, title, date, description) VALUES ($1, $2, $3, $4)`,
      [event.id, event.title, event.date, event.description]
    );
  }

  // Categorias
  const categories = ['coral', 'Olimcemtn', 'poesias', 'obras', 'do (previamnte)'];
  for (const name of categories) {
    await client.query(
      `INSERT INTO categories (id, name, slug, "createdAt") VALUES ($1, $2, $3, $4)`,
      [
        randomUUID(),
        name,
        name.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9-]/g, ''),
        now,
      ]
    );
  }

  // Créditos
  await client.query(
    `INSERT INTO credits (id, description, authors) VALUES ($1, $2, $3)`,
    [
      randomUUID(),
      'Jornal digital do Centro de Ensino Médio Taguatinga Norte.',
      JSON.stringify(['Equipe Jornal Cemtn']),
    ]
  );

  console.log('Dados iniciais inseridos com sucesso.');
}

function runAsync(sql, params = []) {
  return new Promise((resolve, reject) => {
    pool.query(sql, params, (err, result) => {
      if (err) reject(err);
      else resolve({ lastID: result?.rows?.[0]?.id, changes: result?.rowCount });
    });
  });
}

function getAsync(sql, params = []) {
  return new Promise((resolve, reject) => {
    pool.query(sql, params, (err, result) => {
      if (err) reject(err);
      else resolve(result?.rows?.[0]);
    });
  });
}

function allAsync(sql, params = []) {
  return new Promise((resolve, reject) => {
    pool.query(sql, params, (err, result) => {
      if (err) reject(err);
      else resolve(result?.rows || []);
    });
  });
}

module.exports = { db: pool, pool, runAsync, getAsync, allAsync, initializeDatabase };