const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const path = require('path');

const app = express();
const PORT = 3000;
const SALT_ROUNDS = 10;
const LOGIN_EXPIRE_MS = 30 * 60 * 1000;

// ========== CORS跨域配置（核心，允许github pages访问接口） ==========
app.use((req, res, next) => {
  // 允许你的github pages域名
  res.header('Access-Control-Allow-Origin', 'https://a-de4lt.github.io');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  res.header('Access-Control-Allow-Credentials', 'true');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

app.use(cookieParser());
app.use(express.json());

const db = new sqlite3.Database('./database.db', (err) => {
  if (err) console.error('数据库错误：', err.message);
  else console.log('数据库连接成功');
});

db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  last_active INTEGER
)`);

// 初始化管理员账号 admin / 123456
db.get("SELECT * FROM users WHERE username='admin'", async (err, row) => {
  if (!row) {
    const hashPwd = await bcrypt.hash('123456', SALT_ROUNDS);
    db.run("INSERT INTO users (username,password,role,last_active) VALUES (?,?,?,?)",
      ['admin', hashPwd, 'admin', Date.now()]);
  }
});

// 登录校验中间件
async function authCheck(req, res, next) {
  const uid = req.cookies.uid;
  const role = req.cookies.role;
  if (!uid || !role) {
    return res.json({ code: -1, msg: '未登录' });
  }
  db.get("SELECT * FROM users WHERE id=?", [uid], async (err, user) => {
    if (err || !user) return res.json({ code: -1, msg: '用户不存在' });
    const now = Date.now();
    if (now - user.last_active > LOGIN_EXPIRE_MS) {
      res.clearCookie('uid');
      res.clearCookie('role');
      res.clearCookie('username');
      return res.json({ code: -2, msg: '登录已超时，请重新登录' });
    }
    db.run("UPDATE users SET last_active=? WHERE id=?", [now, uid]);
    req.user = user;
    next();
  })
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.json({ code: 0, msg: '无管理员权限' });
  }
  next();
}

// 注册接口
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.json({ code: 0, msg: '账号密码不能为空' });
  try {
    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    db.run("INSERT INTO users (username,password,role,last_active) VALUES (?,?,?,?)",
      [username, hash, 'user', Date.now()], function (err) {
        if (err) return res.json({ code: 0, msg: '账号已存在' });
        res.json({ code: 1, msg: '注册成功，请登录' });
      })
  } catch (e) {
    res.json({ code: 0, msg: '注册异常' });
  }
})

// 登录接口
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT * FROM users WHERE username=?", [username], async (err, user) => {
    if (err || !user) return res.json({ code: 0, msg: '账号或密码错误' });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.json({ code: 0, msg: '账号或密码错误' });
    db.run("UPDATE users SET last_active=? WHERE id=?", [Date.now(), user.id]);
    res.cookie('uid', user.id, { maxAge: LOGIN_EXPIRE_MS, sameSite:'none', secure:true });
    res.cookie('role', user.role, { maxAge: LOGIN_EXPIRE_MS, sameSite:'none', secure:true });
    res.cookie('username', user.username, { maxAge: LOGIN_EXPIRE_MS, sameSite:'none', secure:true });
    res.json({ code: 1, role: user.role, msg: '登录成功' });
  })
})

// 退出登录
app.get('/api/logout', (req, res) => {
  res.clearCookie('uid', {sameSite:'none', secure:true});
  res.clearCookie('role', {sameSite:'none', secure:true});
  res.clearCookie('username', {sameSite:'none', secure:true});
  res.json({code:1, msg:'已退出'});
})

// 用户列表
app.get('/api/userlist', authCheck, adminOnly, (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const pageSize = 8;
  const keyword = req.query.keyword || '';
  const offset = (page - 1) * pageSize;
  let sql = "SELECT id,username,role FROM users";
  let countSql = "SELECT COUNT(*) AS total FROM users";
  let params = [];
  if (keyword) {
    sql += " WHERE username LIKE ?";
    countSql += " WHERE username LIKE ?";
    params.push(`%${keyword}%`);
  }
  sql += " LIMIT ? OFFSET ?";
  params.push(pageSize, offset);

  db.get(countSql, params.slice(0, keyword?1:0), (err, cntRow) => {
    db.all(sql, params, (err, list) => {
      res.json({
        code: 1,
        data: list,
        total: cntRow.total,
        page,
        pageSize
      })
    })
  })
})

// 删除用户
app.post('/api/deluser', authCheck, adminOnly, (req, res) => {
  const { id } = req.body;
  db.get("SELECT * FROM users WHERE id=?", [id], (err, u) => {
    if (u && u.role === 'admin') return res.json({ code: 0, msg: '管理员不可删除' });
    db.run("DELETE FROM users WHERE id=?", [id], e => {
      if (e) return res.json({ code: 0, msg: '删除失败' });
      res.json({ code: 1, msg: '删除成功' });
    })
  })
})

// 修改用户名
app.post('/api/admin-edit-name', authCheck, adminOnly, (req, res) => {
  const { id, newName } = req.body;
  db.run("UPDATE users SET username=? WHERE id=?", [newName, id], err => {
    if (err) return res.json({ code: 0, msg: '用户名重复或者修改失败' });
    res.json({ code: 1, msg: '用户名修改成功' });
  })
})

// 管理员重置密码
app.post('/api/admin-reset-pwd', authCheck, adminOnly, async (req, res) => {
  const { id, newPwd } = req.body;
  const hash = await bcrypt.hash(newPwd, SALT_ROUNDS);
  db.run("UPDATE users SET password=? WHERE id=?", [hash, id], err => {
    if (err) return res.json({ code: 0, msg: '重置失败' });
    res.json({ code: 1, msg: '密码重置成功' });
  })
})

// 用户自己修改密码
app.post('/api/user-change-pwd', authCheck, async (req, res) => {
  const { oldPwd, newPwd } = req.body;
  const user = req.user;
  const passOk = await bcrypt.compare(oldPwd, user.password);
  if (!passOk) return res.json({ code: 0, msg: '原密码错误' });
  const hash = await bcrypt.hash(newPwd, SALT_ROUNDS);
  db.run("UPDATE users SET password=? WHERE id=?", [hash, user.id], err => {
    if (err) return res.json({ code: 0, msg: '修改失败' });
    res.json({ code: 1, msg: '密码修改成功，请重新登录' });
  })
})

app.listen(PORT, () => {
  console.log(`后端接口服务启动：http://127.0.0.1:${PORT}`);
})
