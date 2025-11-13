// server.js - VERSÃO 100% COMPLETA (CORRIGIDO: 4Err00 e Cadastro de Endereço)

require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const multer = require('multer');
const fs = require('fs');

const app = express();
const port = process.env.PORT || 3000;

// --- CONFIGURAÇÃO DO MULTER ---
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        let dest = 'public/uploads/';
        if (file.fieldname === 'fotoPerfil') {
            dest = 'public/uploads/perfis/';
        }
        fs.mkdirSync(dest, { recursive: true });
        cb(null, dest);
    },
    filename: function (req, file, cb) {
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
            db.run("ALTER TABLE usuarios ADD COLUMN tipo TEXT DEFAULT 'cliente' NOT NULL", () => {});
            db.run("ALTER TABLE usuarios ADD COLUMN telefone TEXT", () => {});
            db.run("ALTER TABLE usuarios ADD COLUMN foto_perfil_url TEXT DEFAULT '/assets/images/placeholder.jpg'", () => {});

            // Tabela de Quadras
            db.run(`CREATE TABLE IF NOT EXISTS quadras (id INTEGER PRIMARY KEY AUTOINCREMENT, nome TEXT NOT NULL, tipo TEXT NOT NULL, imagem_url TEXT)`);
            db.run("ALTER TABLE quadras ADD COLUMN dono_id INTEGER REFERENCES usuarios(id)", () => {});
            db.run("ALTER TABLE quadras ADD COLUMN endereco TEXT", () => {});
            db.run("ALTER TABLE quadras ADD COLUMN horario_func TEXT", () => {});
            db.run("ALTER TABLE quadras ADD COLUMN descricao TEXT", () => {});
            db.run("ALTER TABLE quadras ADD COLUMN horario_abertura TEXT DEFAULT '08:00'", () => {});
            db.run("ALTER TABLE quadras ADD COLUMN horario_fechamento TEXT DEFAULT '22:00'", () => {});
            
            // Tabela de Reservas
            db.run(`CREATE TABLE IF NOT EXISTS reservas (id INTEGER PRIMARY KEY AUTOINCREMENT, quadra_id INTEGER, usuario_id INTEGER, data TEXT NOT NULL, horario TEXT NOT NULL, FOREIGN KEY (quadra_id) REFERENCES quadras (id), FOREIGN KEY (usuario_id) REFERENCES usuarios (id))`);
        });
    }
});

// --- FUNÇÃO HELPER PARA GERAR HORÁRIOS ---
function gerarHorarios(abertura, fechamento) {
    const horarios = [];
    const startHour = abertura ? parseInt(abertura.split(':')[0], 10) : 8;
    const endHour = fechamento ? parseInt(fechamento.split(':')[0], 10) : 22;
    for (let h = startHour; h < endHour; h++) {
        horarios.push(h.toString().padStart(2, '0') + ':00');
    }
    return horarios;
}

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
                console.error("Erro DB Register:", err);
                return res.status(500).json({ message: "Erro ao registrar usuário." });
            }
            res.status(201).json({ message: "Usuário registrado com sucesso!" });
        });
    } catch(error) {
         console.error("Erro Hash Register:", error);
        res.status(500).json({ message: "Erro no servidor." });
    }
});

app.post('/api/auth/login', (req, res) => {
    const { email, senha } = req.body;
    const sql = `SELECT * FROM usuarios WHERE email = ?`;
    db.get(sql, [email], async (err, user) => {
        if (err) {
             console.error("Erro DB Login:", err);
             return res.status(500).json({ message: "Erro ao buscar usuário." });
        }
        if (!user) { return res.status(400).json({ message: "Email ou senha inválidos." }); }
        try {
            if (await bcrypt.compare(senha, user.senha)) {
                const payload = { id: user.id, nome: user.nome, tipo: user.tipo };
                const accessToken = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '24h' });
                res.json({ accessToken: accessToken, userName: user.nome, userType: user.tipo });
            } else { res.status(400).json({ message: "Email ou senha inválidos." }); }
        } catch(error) {
             console.error("Erro Compare Login:", error);
             res.status(500).json({ message: "Erro no servidor." });
        }
    });
});

app.post('/api/auth/forgot-password', (req, res) => {
    const { email } = req.body;
    const sql = `SELECT * FROM usuarios WHERE email = ?`;
    db.get(sql, [email], (err, user) => {
         if (err) {
             console.error("Erro DB Forgot:", err);
             return res.status(200).json({ message: 'Se um e-mail cadastrado foi fornecido, um link foi enviado.' });
         }
        if (!user) { return res.status(200).json({ message: 'Se um e-mail cadastrado foi fornecido, um link foi enviado.' }); }

        const token = crypto.randomBytes(20).toString('hex');
        const expires = Date.now() + 3600000;
        const sqlUpdate = `UPDATE usuarios SET reset_password_token = ?, reset_password_expires = ? WHERE email = ?`;
        db.run(sqlUpdate, [token, expires, email], async (errUpdate) => {
            if (errUpdate) {
                console.error("Erro Update Forgot:", errUpdate);
                return res.status(500).json({ message: "Erro ao salvar token de recuperação." });
            }
            const mailOptions = {
                to: user.email,
                from: process.env.EMAIL_USER,
                subject: 'Recuperação de Senha - EsporteAgenda',
                text: `Link: http://${req.headers.host}/reset-password.html?token=${token}`
            };
            try { await transporter.sendMail(mailOptions); res.status(200).json({ message: 'Se um e-mail cadastrado foi fornecido, um link foi enviado.' }); } 
            catch (error) { console.error("Erro ao enviar email:", error); res.status(500).json({ message: 'Erro ao enviar o email de recuperação.' }); }
        });
    });
});

app.post('/api/auth/reset-password', (req, res) => {
    const { token, senha } = req.body;
    if (!token || !senha) {
        return res.status(400).json({ message: 'Token e nova senha são obrigatórios.' });
    }
    const sql = `SELECT * FROM usuarios WHERE reset_password_token = ? AND reset_password_expires > ?`;
    db.get(sql, [token, Date.now()], async (err, user) => {
         if (err) {
             console.error("Erro DB Reset:", err);
             return res.status(500).json({ message: 'Erro ao verificar o token.' });
         }
        if (!user) { return res.status(400).json({ message: "Token inválido ou expirado." }); }
        try {
            const hashedPassword = await bcrypt.hash(senha, 10);
            const sqlUpdate = `UPDATE usuarios SET senha = ?, reset_password_token = NULL, reset_password_expires = NULL WHERE id = ?`;
            db.run(sqlUpdate, [hashedPassword, user.id], (errUpdate) => {
                if (errUpdate) {
                     console.error("Erro Update Reset:", errUpdate);
                     return res.status(500).json({ message: "Erro ao redefinir a senha." });
                }
                res.status(200).json({ message: "Senha redefinida com sucesso." });
            });
        } catch(error) {
             console.error("Erro Hash Reset:", error);
             res.status(500).json({ message: "Erro ao processar a nova senha." });
        }
    });
});

// --- ROTAS DE PERFIL (PARA CLIENTE E DONO) ---

app.get('/api/meu-perfil', authenticateToken, (req, res) => {
    const usuario_id = req.user.id;
    const sql = `SELECT id, nome, email, telefone, foto_perfil_url, tipo FROM usuarios WHERE id = ?`;
    
    db.get(sql, [usuario_id], (err, row) => {
        if (err) {
            console.error("Erro ao buscar perfil:", err);
            return res.status(500).json({ message: "Erro ao buscar dados do perfil." });
        }
        if (!row) {
            return res.status(404).json({ message: "Usuário não encontrado." });
        }
        res.json(row);
    });
});

app.put('/api/meu-perfil', [authenticateToken, upload.single('fotoPerfil')], async (req, res) => {
    const usuario_id = req.user.id;
    const { nome, email, telefone, senha } = req.body;

    let campos = [];
    let sqlSetPartes = [];

    if (nome) { sqlSetPartes.push('nome = ?'); campos.push(nome); }
    if (email) { sqlSetPartes.push('email = ?'); campos.push(email); }
    if (telefone || telefone === '') { sqlSetPartes.push('telefone = ?'); campos.push(telefone); }

    if (req.file) {
        const foto_url = `/uploads/perfis/${req.file.filename}`;
        sqlSetPartes.push('foto_perfil_url = ?');
        campos.push(foto_url);
    }

    if (senha) {
        try {
            const hashedPassword = await bcrypt.hash(senha, 10);
            sqlSetPartes.push('senha = ?');
            campos.push(hashedPassword);
        } catch (error) {
            return res.status(500).json({ message: "Erro ao processar nova senha." });
        }
    }

    if (campos.length === 0) {
        return res.status(400).json({ message: "Nenhum dado enviado para atualização." });
    }

    const sql = `UPDATE usuarios SET ${sqlSetPartes.join(', ')} WHERE id = ?`;
    campos.push(usuario_id);

    db.run(sql, campos, function(err) {
        if (err) {
            console.error("Erro ao atualizar perfil:", err);
            if (err.message.includes('UNIQUE constraint failed: usuarios.email')) {
                return res.status(409).json({ message: "Este e-mail já está em uso por outra conta." });
            }
            return res.status(500).json({ message: "Erro ao salvar alterações no banco de dados." });
        }
        res.status(200).json({ message: "Perfil atualizado com sucesso!" });
    });
});


// --- ROTAS DE DADOS (PÚBLICAS E DE CLIENTES) ---

app.get('/api/quadras', (req, res) => {
    db.all('SELECT * FROM quadras', [], (err, rows) => {
        if (err) { res.status(500).json({ error: err.message }); return; }
        res.json({ quadras: rows });
    });
});

app.get('/api/horarios/:quadraId/:data', (req, res) => {
    const { quadraId, data } = req.params;
    if (!/^\d+$/.test(quadraId) || !/^\d{4}-\d{2}-\d{2}$/.test(data)) {
        return res.status(400).json({ error: 'Parâmetros inválidos.' });
    }

    db.get('SELECT horario_abertura, horario_fechamento FROM quadras WHERE id = ?', [quadraId], (errQuadra, quadra) => {
        if (errQuadra) {
            console.error("Erro DB Get Horarios (Busca Quadra):", errQuadra);
            return res.status(500).json({ error: errQuadra.message });
        }
        if (!quadra) { return res.status(404).json({ error: 'Quadra não encontrada.' }); }

        const horariosPossiveis = gerarHorarios(quadra.horario_abertura, quadra.horario_fechamento);

        const sql = 'SELECT horario FROM reservas WHERE quadra_id = ? AND data = ?';
        db.all(sql, [quadraId, data], (err, rows) => {
            if (err) {
                console.error("Erro DB Get Horarios (Busca Reservas):", err);
                res.status(500).json({ error: err.message }); return;
            }
            const horariosReservados = rows.map(row => row.horario);
            const horariosLivres = horariosPossiveis.filter(h => !horariosReservados.includes(h));
            res.json({ horarios: horariosLivres });
        });
    });
});

app.post('/api/horarios-multi', [authenticateToken], (req, res) => {
    const { quadraId, dates } = req.body;
    if (!quadraId || !Array.isArray(dates) || dates.length === 0) {
        return res.status(400).json({ error: 'ID da quadra e um array de datas são obrigatórios.' });
    }
    if (!dates.every(date => /^\d{4}-\d{2}-\d{2}$/.test(date))) {
         return res.status(400).json({ error: 'Formato de data inválido. Use AAAA-MM-DD.' });
    }

    db.get('SELECT horario_abertura, horario_fechamento FROM quadras WHERE id = ?', [quadraId], (errQuadra, quadra) => {
        if (errQuadra) {
            console.error("Erro DB Get Horarios-Multi (Busca Quadra):", errQuadra);
            return res.status(500).json({ error: errQuadra.message });
        }
        if (!quadra) { return res.status(404).json({ error: 'Quadra não encontrada.' }); }

        const horariosPossiveis = gerarHorarios(quadra.horario_abertura, quadra.horario_fechamento);

        const placeholders = dates.map(() => '?').join(',');
        const sql = `SELECT data, horario FROM reservas WHERE quadra_id = ? AND data IN (${placeholders})`;

        db.all(sql, [quadraId, ...dates], (err, rows) => {
            if (err) {
                console.error("Erro ao buscar reservas múltiplas:", err);
                return res.status(500).json({ error: "Erro ao consultar banco de dados." });
            }
            
            const horariosOcupadosPorData = {};
            dates.forEach(date => { horariosOcupadosPorData[date] = new Set(); });
            rows.forEach(row => {
                if(horariosOcupadosPorData[row.data]) {
                     horariosOcupadosPorData[row.data].add(row.horario);
                }
            });
            
            const horariosComuns = horariosPossiveis.filter(horario => {
                return dates.every(date => !horariosOcupadosPorData[date].has(horario));
            });
            res.json({ horariosComuns: horariosComuns });
        });
    });
});

app.post('/api/reservas', [authenticateToken, authorizeCliente], (req, res) => {
    const { reservas } = req.body;
    const usuario_id = req.user.id;

    if (!Array.isArray(reservas) || reservas.length === 0) {
        return res.status(400).json({ message: 'Formato de dados inválido ou nenhuma reserva enviada.' });
    }

    const resultados = [];
    let houveErroGrave = false;
    let houveConflito = false;

    db.serialize(() => {
        db.run('BEGIN TRANSACTION;', (err) => {
            if (err) {
                 console.error("Erro ao iniciar transação:", err);
                 return res.status(500).json({ message: 'Erro interno no servidor (transação).' });
            }

            const promessas = reservas.map(reserva => {
                return new Promise((resolve, reject) => {
                    const { quadra_id, data, horario } = reserva;
                    if (!quadra_id || !data || !horario || !/^\d{4}-\d{2}-\d{2}$/.test(data) || !/^\d{2}:\d{2}$/.test(horario)) {
                        return resolve({ success: false, data, horario, message: 'Dados incompletos ou inválidos.' });
                    }

                    const checkSql = 'SELECT id FROM reservas WHERE quadra_id = ? AND data = ? AND horario = ?';
                    db.get(checkSql, [quadra_id, data, horario], (errCheck, row) => {
                        if (errCheck) {
                            console.error(`Erro ao verificar ${data} ${horario}:`, errCheck);
                            return reject(new Error(`Erro DB ao verificar ${data} ${horario}`));
                        }
                        if (row) {
                            return resolve({ success: false, data, horario, message: 'Horário já reservado.' });
                        }

                        const insertSql = 'INSERT INTO reservas (quadra_id, usuario_id, data, horario) VALUES (?, ?, ?, ?)';
                        db.run(insertSql, [quadra_id, usuario_id, data, horario], function(errInsert) {
                            if (errInsert) {
                                console.error(`Erro ao inserir ${data} ${horario}:`, errInsert);
                                return reject(new Error(`Erro DB ao inserir ${data} ${horario}`));
                            }
                            resolve({ success: true, data, horario, id: this.lastID });
                        });
                    });
                });
            });

            Promise.allSettled(promessas)
                .then(results => {
                    results.forEach(result => {
                        if (result.status === 'fulfilled') {
                            resultados.push(result.value);
                            if (!result.value.success && result.value.message === 'Horário já reservado.') {
                                houveConflito = true;
                            } else if (!result.value.success) {
                                houveErroGrave = true;
                            }
                        } else {
                            console.error("Promise rejeitada:", result.reason);
                            houveErroGrave = true;
                            resultados.push({ success: false, message: result.reason.message || 'Erro interno.' });
                        }
                    });

                    if (houveErroGrave || houveConflito) {
                        db.run('ROLLBACK;', (rollbackErr) => {
                             if (rollbackErr) console.error("Erro no ROLLBACK:", rollbackErr);
                             res.status(409).json({ message: 'Alguns horários não puderam ser reservados.', details: resultados });
                        });
                    } else {
                        db.run('COMMIT;', (commitErr) => {
                            if (commitErr) {
                                console.error("Erro no COMMIT:", commitErr);
                                db.run('ROLLBACK;');
                                return res.status(500).json({ message: 'Erro ao confirmar reservas.' });
                            }
                            res.status(201).json({ message: 'Todas as reservas foram criadas com sucesso!', details: resultados });
                        });
                    }
                });
        });
    });
});

// --- ROTAS EXCLUSIVAS PARA DONOS DE QUADRA ---

// ----- ROTA POST /api/quadras (CORRIGIDA PARA INCLUIR 'endereco') -----
app.post('/api/quadras', [authenticateToken, authorizeDono, upload.single('quadraImage')], (req, res) => {
    // Pega todos os novos campos do formulário
    const { nome, tipo, descricao, horario_abertura, horario_fechamento, endereco } = req.body;
    const dono_id = req.user.id;

    if (!nome || !tipo || !descricao || !horario_abertura || !horario_fechamento || !endereco) {
        return res.status(400).json({ message: 'Todos os campos (nome, tipo, descrição, horários e endereço) são obrigatórios.' });
    }
    if (!req.file) {
        return res.status(400).json({ message: 'A imagem da quadra é obrigatória.' });
    }

    const imagem_url = `/uploads/${req.file.filename}`;

    // Atualiza o SQL para incluir todos os campos
    const sql = `INSERT INTO quadras (nome, tipo, imagem_url, dono_id, descricao, horario_abertura, horario_fechamento, endereco, horario_func) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`;
    // Preenche com valores (horario_func fica vazio por enquanto, já que temos os horários específicos)
    db.run(sql, [nome, tipo, imagem_url, dono_id, descricao, horario_abertura, horario_fechamento, endereco, ''], function(err) {
        if (err) {
             console.error("Erro DB Insert Quadra:", err);
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
             console.error("Erro DB Get Minhas Quadras:", err);
             return res.status(500).json({ error: err.message });
        }
        res.json({ quadras: rows });
    });
});

app.get('/api/dono/reservas', [authenticateToken, authorizeDono], (req, res) => {
    const dono_id = req.user.id;
    const sql = `
        SELECT
            r.id, r.data, r.horario,
            u.nome AS cliente_nome,
            q.nome AS quadra_nome
        FROM reservas r
        JOIN usuarios u ON r.usuario_id = u.id
        JOIN quadras q ON r.quadra_id = q.id
        WHERE q.dono_id = ?
        ORDER BY r.data DESC, r.horario DESC
    `;
    db.all(sql, [dono_id], (err, rows) => {
        if (err) {
             console.error("Erro DB Get Reservas Dono:", err);
             return res.status(500).json({ error: err.message });
        }
        res.json({ reservas: rows });
    });
});

app.delete('/api/quadras/:id', [authenticateToken, authorizeDono], (req, res) => {
    const quadraId = req.params.id;
    const dono_id = req.user.id;

    if (!/^\d+$/.test(quadraId)){
        return res.status(400).json({ message: "ID da quadra inválido." });
    }

    const sqlVerify = `SELECT dono_id FROM quadras WHERE id = ?`;
    db.get(sqlVerify, [quadraId], (err, quadra) => {
         if (err) {
             console.error("Erro DB Verify Delete Quadra:", err);
             return res.status(500).json({ message: "Erro ao verificar a quadra." });
         }
        if (!quadra) { return res.status(404).json({ message: "Quadra não encontrada." }); }
        if (quadra.dono_id !== dono_id) { return res.status(403).json({ message: "Você não tem permissão para apagar esta quadra." }); }

        db.serialize(() => {
             db.run('BEGIN TRANSACTION;');
             db.run(`DELETE FROM reservas WHERE quadra_id = ?`, [quadraId], function(errDelRes) {
                 if (errDelRes) {
                     console.error("Erro DB Delete Reservas Assoc:", errDelRes);
                     db.run('ROLLBACK;');
                     return res.status(500).json({ message: "Erro ao apagar as reservas associadas." });
                 }
                 db.run(`DELETE FROM quadras WHERE id = ?`, [quadraId], function(errDelQua) {
                     if (errDelQua) {
                          console.error("Erro DB Delete Quadra:", errDelQua);
                          db.run('ROLLBACK;');
                         return res.status(500).json({ message: "Erro ao apagar a quadra." });
                     }
                      db.run('COMMIT;', (commitErr) => {
                           if(commitErr) {
                                console.error("Erro no commit ao apagar quadra:", commitErr);
                                db.run('ROLLBACK;');
                                return res.status(500).json({ message: 'Erro ao confirmar exclusão da quadra.' });
                           }
                            res.status(200).json({ message: "Quadra e suas reservas foram apagadas com sucesso." });
                      });
                 });
             });
        });
    });
});

app.get('/api/quadra-detalhes/:id', [authenticateToken, authorizeDono], (req, res) => {
    const quadraId = req.params.id;
    const dono_id = req.user.id;
    
    if (!/^\d+$/.test(quadraId)){
        // ----- LINHA CORRIGIDA (REMOVIDO O ERRO '4Err00') -----
        return res.status(400).json({ message: "ID da quadra inválido." });
    }

    const sql = `SELECT * FROM quadras WHERE id = ? AND dono_id = ?`;
    db.get(sql, [quadraId, dono_id], (err, row) => {
        if (err) {
             console.error("Erro DB Get Detalhes Quadra:", err);
            return res.status(500).json({ message: "Erro ao buscar dados da quadra." });
        }
        if (!row) {
            return res.status(403).json({ message: "Quadra não encontrada ou você não tem permissão para editá-la." });
        }
        res.json(row);
    });
});

app.put('/api/quadra-detalhes/:id', [authenticateToken, authorizeDono], (req, res) => {
    const quadraId = req.params.id;
    const dono_id = req.user.id;
    // ----- CORRIGIDO: Removido 'horario_func' da validação -----
    const { nome, endereco, horario_func, descricao, horario_abertura, horario_fechamento } = req.body;

    if (!/^\d+$/.test(quadraId)){
        return res.status(400).json({ message: "ID da quadra inválido." });
    }
    // ----- CORRIGIDO: Removido 'horario_func' da validação -----
    if (!nome || !endereco || !descricao || !horario_abertura || !horario_fechamento) {
        return res.status(400).json({ message: "Todos os campos (exceto Horário de Funcionamento em texto) são obrigatórios." });
    }

    const sqlVerify = `SELECT dono_id FROM quadras WHERE id = ?`;
    db.get(sqlVerify, [quadraId], (err, quadra) => {
         if (err) {
             console.error("Erro DB Verify Update Quadra:", err);
             return res.status(500).json({ message: "Erro ao verificar a quadra." });
         }
        if (!quadra) {
            return res.status(404).json({ message: "Quadra não encontrada." });
        }
        if (quadra.dono_id !== dono_id) {
            return res.status(403).json({ message: "Você não tem permissão para editar esta quadra." });
        }

        // ----- CORRIGIDO: Atualiza 'horario_func' com o valor recebido (pode ser vazio) e remove da validação estrita -----
        const sqlUpdate = `UPDATE quadras SET 
            nome = ?, 
            endereco = ?, 
            horario_func = ?, 
            descricao = ?, 
            horario_abertura = ?, 
            horario_fechamento = ? 
        WHERE id = ? AND dono_id = ?`;
        
        // Passa o 'horario_func' recebido (pode ser vazio, já que o removemos do formulário de edição)
        db.run(sqlUpdate, [nome, endereco, horario_func || '', descricao, horario_abertura, horario_fechamento, quadraId, dono_id], function(errUpdate) {
            if (errUpdate) {
                 console.error("Erro DB Update Quadra:", errUpdate);
                return res.status(500).json({ message: "Erro ao salvar as alterações da quadra." });
            }
            res.status(200).json({ message: "Quadra atualizada com sucesso!" });
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