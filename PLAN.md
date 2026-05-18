# 钏钏选标器 v7.0 — 升级架构设计

## 数据库 (SQLite)

```sql
-- 用户表
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    risk_level TEXT DEFAULT NULL  -- 'conservative','moderate','aggressive'
);

-- 会话表 (token-based, 30天过期)
CREATE TABLE sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

-- 自选标的表
CREATE TABLE watchlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    symbol TEXT NOT NULL,       -- 'BTC','AAPL','600519.SS'等
    type TEXT NOT NULL,         -- 'crypto','stock'
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id),
    UNIQUE(user_id, symbol)
);
```

## API 设计

| Method | Path | Auth | 说明 |
|--------|------|------|------|
| POST | /api/auth/register | No | 注册 {username, password, confirm_password} |
| POST | /api/auth/login | No | 登录 {username, password} → {token, risk_level} |
| POST | /api/auth/logout | Yes | 登出 |
| GET  | /api/auth/me | Yes | 当前用户信息 |
| POST | /api/risk/save | Yes | 保存风险评估结果 {answers[], score, level} |
| GET  | /api/risk/result | Yes | 获取已保存的风险评估 |
| GET  | /api/watchlist | Yes | 获取自选列表 |
| POST | /api/watchlist | Yes | 添加自选 {symbol, type} |
| DELETE|/api/watchlist/{symbol}|Yes| 删除自选 |
| GET  | /api/hot-news | No | 热点新闻（聚合） |
| GET  | /api/main-themes | No | 主线行情 |
| GET  | /api/wealth/recommend | Yes | 理财推荐（基于风险等级） |

## 前端改造

### 图表库
- 替换 Canvas 手写图表为 **TradingView Lightweight Charts™**
- 支持：缩放（滚轮）、平移（拖拽）、十字光标（crosshair）、时间范围切换

### 新增页面/Tab
- 登录/注册模态框
- 自选页面（watchlist tab）
- 快捷入口改为4卡片：理财推荐/热点新闻/主线行情/个股诊断

### 风险门控
- 风险评估结果存储到后端
- 登录后未评估 → 引导评估
- conservative: 不可见山寨币tab
- moderate: 可见山寨币但有限制提示
- aggressive: 全部功能开放

## 标题修改
- 主标题：「钏钏选标器」
- 去掉「の神奇买卖点」
- 去掉副标题中的「实时行情 · Canvas 专业图表 · AI 智能分析 · 多周期 · 风险评估」
