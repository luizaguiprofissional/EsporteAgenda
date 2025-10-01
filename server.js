// server.js - VERSÃO 100% COMPLETA E SEM ABREVIAÇÕES

require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const multer = require('multer');

const app = express();
const port = 3000;

// --- CONFIGURAÇÃO DO MULTER ---
// Define onde e como os arquivos de imagem serão salvos
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'public/uploads/'); // Salva os arquivos na pasta 'public/uploads'
    },
    filename: function (req, file, cb) {
        // Cria um nome de arquivo único para evitar nomes duplicados
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const extensao = path.extname(file.originalname);
        cb(null, file.fieldname + '-' + uniqueSuffix + extensao);
    }
});
const upload = multer({ storage: storage });


// Middlewares
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public'))); 

// --- Configuração do Banco de Dados ---
const dbPath = path.join(__dirname, 'database', 'database.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Erro ao conectar ao banco de dados:', err.message);
    } else {
        console.log('Conectado ao banco de dados SQLite.');
        db.serialize(() => {
            // Tabela de Usuários
            db.run(`CREATE TABLE IF NOT EXISTS usuarios (id INTEGER PRIMARY KEY AUTOINCREMENT, nome TEXT NOT NULL, email TEXT UNIQUE NOT NULL, senha TEXT NOT NULL, reset_password_token TEXT, reset_password_expires INTEGER)`);
            
            // Tabela de Quadras
            db.run(`CREATE TABLE IF NOT EXISTS quadras (id INTEGER PRIMARY KEY AUTOINCREMENT, nome TEXT NOT NULL, tipo TEXT NOT NULL, imagem_url TEXT)`);

            // Tabela de Reservas
            db.run(`CREATE TABLE IF NOT EXISTS reservas (id INTEGER PRIMARY KEY AUTOINCREMENT, quadra_id INTEGER, usuario_id INTEGER, data TEXT NOT NULL, horario TEXT NOT NULL, FOREIGN KEY (quadra_id) REFERENCES quadras (id), FOREIGN KEY (usuario_id) REFERENCES usuarios (id))`);

            // --- ALTERAÇÕES NO BANCO DE DADOS PARA PERFIS ---
            db.run("ALTER TABLE usuarios ADD COLUMN tipo TEXT DEFAULT 'cliente' NOT NULL", () => {});
            db.run("ALTER TABLE quadras ADD COLUMN dono_id INTEGER REFERENCES usuarios(id)", () => {});

            // Insere dados de exemplo para quadras (se não existirem)
            const sql_insert = `INSERT OR IGNORE INTO quadras (id, nome, tipo, imagem_url) VALUES 
                (1, 'Quadra de Tênis A', 'Saibro', '/assets/images/quadra-tenis.jpg'), 
                (2, 'Quadra Poliesportiva B', 'Cimento', '/assets/images/quadra-poliesportiva.jpg'),
                (3, 'Campo de Futebol Society', 'Grama Sintética', '/assets/images/campo-society.jpg')`;
            db.run(sql_insert);
        });
    }
});

// --- Configuração do Nodemailer ---
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// --- Middlewares de Autenticação e Autorização ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

const authorizeDono = (req, res, next) => {
    if (req.user.tipo !== 'dono') {
        return res.status(403).json({ message: 'Acesso negado. Apenas para donos de quadra.' });
    }
    next();
};

const authorizeCliente = (req, res, next) => {
    if (req.user.tipo !== 'cliente') {
        return res.status(403).json({ message: 'Acesso negado. Apenas para clientes.' });
    }
    next();
};


// ================== ROTAS DA API ==================

// --- ROTAS DE AUTENTICAÇÃO ---

app.post('/api/auth/register', async (req, res) => {
    const { nome, email, senha, tipo } = req.body;
    if (!nome || !email || !senha || !tipo) {
        return res.status(400).json({ message: "Todos os campos são obrigatórios." });
    }
    if (tipo !== 'cliente' && tipo !== 'dono') {
        return res.status(400).json({ message: "Tipo de usuário inválido." });
    }

    try {
        const hashedPassword = await bcrypt.hash(senha, 10);
        const sql = `INSERT INTO usuarios (nome, email, senha, tipo) VALUES (?, ?, ?, ?)`;
        db.run(sql, [nome, email, hashedPassword, tipo], function(err) {
            if (err) {
                if (err.message.includes('UNIQUE constraint failed')) {
                    return res.status(409).json({ message: "Este e-mail já está cadastrado." });
                }
                return res.status(500).json({ message: "Erro ao registrar usuário." });
            }
            res.status(201).json({ message: "Usuário registrado com sucesso!" });
        });
    } catch {
        res.status(500).json({ message: "Erro no servidor." });
    }
});

app.post('/api/auth/login', (req, res) => {
    const { email, senha } = req.body;
    const sql = `SELECT * FROM usuarios WHERE email = ?`;
    
    db.get(sql, [email], async (err, user) => {
        if (err || !user) {
            return res.status(400).json({ message: "Email ou senha inválidos." });
        }
        
        try {
            if (await bcrypt.compare(senha, user.senha)) {
                const payload = { id: user.id, nome: user.nome, tipo: user.tipo };
                const accessToken = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '24h' });
                res.json({ accessToken: accessToken, userName: user.nome, userType: user.tipo });
            } else {
                res.status(400).json({ message: "Email ou senha inválidos." });
            }
        } catch {
            res.status(500).json({ message: "Erro no servidor." });
        }
    });
});

app.post('/api/auth/forgot-password', (req, res) => {
    const { email } = req.body;
    const sql = `SELECT * FROM usuarios WHERE email = ?`;

    db.get(sql, [email], (err, user) => {
        if (err || !user) {
            return res.status(200).json({ message: 'Email de recuperação enviado com sucesso.' });
        }
        
        const token = crypto.randomBytes(20).toString('hex');
        const expires = Date.now() + 3600000;

        const sqlUpdate = `UPDATE usuarios SET reset_password_token = ?, reset_password_expires = ? WHERE email = ?`;
        db.run(sqlUpdate, [token, expires, email], async (err) => {
            if (err) {
                return res.status(500).json({ message: "Erro ao salvar token de recuperação." });
            }

            const mailOptions = {
                to: user.email,
                from: process.env.EMAIL_USER,
                subject: 'Recuperação de Senha - Reserva de Quadras',
                text: `Você está recebendo este e-mail porque solicitou a redefinição de senha.\n\n` +
                      `Por favor, clique no link a seguir ou cole no seu navegador para completar o processo:\n\n` +
                      `http://${req.headers.host}/reset-password.html?token=${token}\n\n` +
                      `Se você não solicitou isso, por favor, ignore este e-mail.\n`
            };
            
            try {
                await transporter.sendMail(mailOptions);
                res.status(200).json({ message: 'Email de recuperação enviado com sucesso.' });
            } catch (error) {
                res.status(500).json({ message: 'Erro ao enviar o email.' });
            }
        });
    });
});

app.post('/api/auth/reset-password', (req, res) => {
    const { token, senha } = req.body;
    const sql = `SELECT * FROM usuarios WHERE reset_password_token = ? AND reset_password_expires > ?`;

    db.get(sql, [token, Date.now()], async (err, user) => {
        if (err || !user) {
            return res.status(400).json({ message: "Token inválido ou expirado." });
        }
        
        const hashedPassword = await bcrypt.hash(senha, 10);
        const sqlUpdate = `UPDATE usuarios SET senha = ?, reset_password_token = NULL, reset_password_expires = NULL WHERE id = ?`;

        db.run(sqlUpdate, [hashedPassword, user.id], (err) => {
            if (err) {
                return res.status(500).json({ message: "Erro ao redefinir a senha." });
            }
            res.status(200).json({ message: "Senha redefinida com sucesso." });
        });
    });
});

// --- ROTAS DE DADOS (PÚBLICAS E DE CLIENTES) ---

app.get('/api/quadras', (req, res) => {
    db.all('SELECT * FROM quadras', [], (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json({ quadras: rows });
    });
});

app.get('/api/horarios/:quadraId/:data', (req, res) => {
    const { quadraId, data } = req.params;
    const horariosDisponiveis = ['08:00', '09:00', '10:00', '11:00', '12:00', '13:00', '14:00', '15:00', '16:00', '17:00', '18:00', '19:00', '20:00', '21:00'];
    const sql = 'SELECT horario FROM reservas WHERE quadra_id = ? AND data = ?';
    
    db.all(sql, [quadraId, data], (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        const horariosReservados = rows.map(row => row.horario);
        const horariosLivres = horariosDisponiveis.filter(h => !horariosReservados.includes(h));
        res.json({ horarios: horariosLivres });
    });
});

app.post('/api/reservas', [authenticateToken, authorizeCliente], (req, res) => {
    const { quadra_id, data, horario } = req.body;
    const usuario_id = req.user.id;
    const sql = 'INSERT INTO reservas (quadra_id, usuario_id, data, horario) VALUES (?, ?, ?, ?)';
    db.run(sql, [quadra_id, usuario_id, data, horario], function (err) {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.status(201).json({ message: 'Reserva criada com sucesso!', id: this.lastID });
    });
});

// --- ROTAS EXCLUSIVAS PARA DONOS DE QUADRA ---

app.post('/api/quadras', [authenticateToken, authorizeDono, upload.single('quadraImage')], (req, res) => {
    const { nome, tipo } = req.body;
    const dono_id = req.user.id;

    if (!nome || !tipo) {
        return res.status(400).json({ message: 'Nome e tipo são obrigatórios.' });
    }
    if (!req.file) {
        return res.status(400).json({ message: 'A imagem da quadra é obrigatória.' });
    }

    const imagem_url = `/uploads/${req.file.filename}`;

    const sql = `INSERT INTO quadras (nome, tipo, imagem_url, dono_id) VALUES (?, ?, ?, ?)`;
    db.run(sql, [nome, tipo, imagem_url, dono_id], function(err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.status(201).json({ message: 'Quadra cadastrada com sucesso!', id: this.lastID });
    });
});

app.get('/api/minhas-quadras', [authenticateToken, authorizeDono], (req, res) => {
    const dono_id = req.user.id;
    const sql = `SELECT * FROM quadras WHERE dono_id = ?`;
    
    db.all(sql, [dono_id], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ quadras: rows });
    });
});

app.get('/api/dono/reservas', [authenticateToken, authorizeDono], (req, res) => {
    const dono_id = req.user.id;

    const sql = `
        SELECT 
            reservas.id, 
            reservas.data, 
            reservas.horario, 
            usuarios.nome AS cliente_nome, 
            quadras.nome AS quadra_nome
        FROM reservas
        JOIN usuarios ON reservas.usuario_id = usuarios.id
        JOIN quadras ON reservas.quadra_id = quadras.id
        WHERE quadras.dono_id = ?
        ORDER BY reservas.data DESC, reservas.horario DESC
    `;

    db.all(sql, [dono_id], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ reservas: rows });
    });
});

app.delete('/api/quadras/:id', [authenticateToken, authorizeDono], (req, res) => {
    const quadraId = req.params.id;
    const dono_id = req.user.id;

    const sqlVerify = `SELECT dono_id FROM quadras WHERE id = ?`;
    db.get(sqlVerify, [quadraId], (err, quadra) => {
        if (err) {
            return res.status(500).json({ message: "Erro ao verificar a quadra." });
        }
        if (!quadra) {
            return res.status(404).json({ message: "Quadra não encontrada." });
        }
        if (quadra.dono_id !== dono_id) {
            return res.status(403).json({ message: "Você não tem permissão para apagar esta quadra." });
        }

        db.serialize(() => {
            db.run(`DELETE FROM reservas WHERE quadra_id = ?`, [quadraId], function(err) {
                if (err) {
                    return res.status(500).json({ message: "Erro ao apagar as reservas associadas." });
                }
                db.run(`DELETE FROM quadras WHERE id = ?`, [quadraId], function(err) {
                    if (err) {
                        return res.status(500).json({ message: "Erro ao apagar a quadra." });
                    }
                    res.status(200).json({ message: "Quadra e suas reservas foram apagadas com sucesso." });
                });
            });
        });
    });
});


// --- ROTA PRINCIPAL E INÍCIO DO SERVIDOR ---

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'home.html'));
});

app.listen(port, () => {
    console.log(`Servidor rodando em http://localhost:${port}`);
});