// ============================================
// ИМПОРТЫ И НАСТРОЙКИ
// ============================================
import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pool, { query, checkConnection, getPoolStats } from './lib/db.js';
import { createClient } from '@supabase/supabase-js';
import multer from 'multer';

// Конфигурация multer для загрузки файлов
const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Только изображения!'), false);
        }
    }
});

// Инициализация клиентов Supabase
const supabasePublic = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_ANON_KEY
);

const supabaseAdmin = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY,
    {
        auth: {
            autoRefreshToken: false,
            persistSession: false
        }
    }
);

// Клиент для работы с Storage
const supabaseStorage = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_ANON_KEY
);

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET;

// ============================================
// MIDDLEWARE
// ============================================
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Логирование запросов
app.use((req, res, next) => {
    console.log(`[LOG] ${req.method} ${req.path}`);
    next();
});

// ============================================
// MIDDLEWARE: ПРОВЕРКА ПРАВ АДМИНА
// ============================================
function adminMiddleware(req, res, next) {
    try {
        const token = req.headers['authorization']?.replace('Bearer ', '');
        if (!token) {
            return res.status(401).json({ error: 'Требуется авторизация' });
        }
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key-change-in-production');
        if (decoded.role !== 'admin') {
            return res.status(403).json({ error: 'Требуется роль администратора' });
        }
        req.user = decoded;
        next();
    } catch (error) {
        console.error('Admin middleware error:', error);
        return res.status(401).json({ error: 'Неверный или истёкший токен' });
    }
}

// ============================================
// MIDDLEWARE ДЛЯ ПРОВЕРКИ ТОКЕНА
// ============================================
const authMiddleware = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'Не авторизован' });
        }
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        console.error('Auth error:', error.message);
        res.status(401).json({ error: 'Неверный токен' });
    }
};

// ============================================
// HEALTH CHECK
// ============================================
app.get('/api/health', async (req, res) => {
    try {
        const connected = await checkConnection();
        const stats = getPoolStats();
        res.json({
            status: connected ? 'ok' : 'error',
            database: connected ? 'connected' : 'disconnected',
            pool: stats,
            time: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({
            status: 'error',
            database: 'disconnected',
            error: error.message
        });
    }
});

// ============================================
// API: СПРАВОЧНИКИ (категории и бренды)
// ============================================
// Получить все категории
app.get('/api/admin/categories', adminMiddleware, async (req, res) => {
    try {
        const result = await query(
            'SELECT id_category, name FROM categories ORDER BY name'
        );
        res.json(result.rows);
    } catch (error) {
        console.error('Get categories error:', error);
        res.status(500).json({ error: 'Ошибка получения категорий' });
    }
});

// Получить все бренды
app.get('/api/admin/brands', adminMiddleware, async (req, res) => {
    try {
        const result = await query(
            'SELECT id_brand, name FROM brands ORDER BY name'
        );
        res.json(result.rows);
    } catch (error) {
        console.error('Get brands error:', error);
        res.status(500).json({ error: 'Ошибка получения брендов' });
    }
});

// ============================================
// API ADMIN: ЗАГРУЗКА ИЗОБРАЖЕНИЙ
// ============================================
app.post('/api/admin/upload-image',
    adminMiddleware,
    upload.single('file'),
    async (req, res) => {
        try {
            if (!req.file) {
                return res.status(400).json({ error: 'Файл не загружен' });
            }
            // Генерируем уникальное имя файла
            const ext = req.file.originalname.split('.').pop();
            const fileName = `${Date.now()}_${Math.random().toString(36).slice(2, 8)}.${ext}`;
            console.log('Uploading file:', fileName);

            // Загружаем в Supabase Storage
            const { data, error: uploadError } = await supabaseAdmin.storage
                .from('products')
                .upload(fileName, req.file.buffer, {
                    contentType: req.file.mimetype,
                    upsert: false,
                    cacheControl: '3600'
                });

            if (uploadError) {
                console.error('Supabase upload error:', uploadError);
                throw uploadError;
            }

            // Получение публичного URL
            const { data: urlData } = supabasePublic.storage
                .from('products')
                .getPublicUrl(fileName);
            const publicUrl = urlData.publicUrl;
            console.log('Image uploaded:', publicUrl);

            res.json({
                success: true,
                url: publicUrl,
                fileName: fileName
            });
        } catch (error) {
            console.error('Upload image error:', error);
            res.status(500).json({
                error: 'Ошибка загрузки изображения',
                details: error.message
            });
        }
    });

// ============================================
// API: ВХОД В АДМИНКУ
// ============================================
app.post('/api/auth/admin-login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ error: 'Email и пароль обязательны' });
        }

        // Поиск пользователя
        const result = await query(
            'SELECT * FROM users WHERE email = $1',
            [email.toLowerCase()]
        );
        if (!result.rows || result.rows.length === 0) {
            return res.status(401).json({ error: 'Неверный email или пароль' });
        }
        const user = result.rows[0];

        // Проверка пароля (bcrypt)
        const isValidPassword = await bcrypt.compare(password, user.password_hash);
        if (!isValidPassword) {
            return res.status(401).json({ error: 'Неверный email или пароль' });
        }

        // Проверка роли админа
        if (user.role !== 'admin') {
            return res.status(403).json({ error: 'Доступ запрещён. Требуется роль администратора' });
        }

        // Создание JWT токена
        const token = jwt.sign(
            {
                userId: user.id_user,
                email: user.email,
                role: user.role,
                firstName: user.first_name
            },
            process.env.JWT_SECRET || 'your-secret-key-change-in-production',
            { expiresIn: '24h' }
        );

        // Возврат данных без пароля
        const { password_hash, ...userWithoutPassword } = user;
        console.log(`Admin login: ${user.email}`);
        res.json({
            token,
            user: userWithoutPassword
        });
    } catch (error) {
        console.error('Admin login error:', error);
        res.status(500).json({
            error: 'Ошибка сервера',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// ============================================
// API ADMIN: ПОЛЬЗОВАТЕЛИ
// ============================================
// Получить всех пользователей (только админ)
app.get('/api/admin/users', adminMiddleware, async (req, res) => {
    try {
        const result = await query(
            'SELECT id_user, first_name, last_name, email, role, created_at FROM users ORDER BY id_user DESC'
        );
        res.json(result.rows);
    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({ error: 'Ошибка получения пользователей' });
    }
});

// Удалить пользователя (только админ)
app.delete('/api/admin/users/:id', adminMiddleware, async (req, res) => {
    try {
        const { id } = req.params;
        const adminId = req.user.userId;

        // Защита от удаления самого себя
        if (id == adminId) {
            return res.status(400).json({ error: 'Нельзя удалить самого себя' });
        }

        // Защита от удаления другого админа
        const targetUser = await query('SELECT role FROM users WHERE id_user = $1', [id]);
        if (targetUser.rows[0]?.role === 'admin') {
            return res.status(403).json({ error: 'Нельзя удалить другого администратора' });
        }

        await query('DELETE FROM users WHERE id_user = $1', [id]);
        console.log(`User ${id} deleted by admin ${adminId}`);
        res.json({ message: 'Пользователь удалён' });
    } catch (error) {
        console.error('Delete user error:', error);
        res.status(500).json({ error: 'Ошибка удаления пользователя' });
    }
});

// Изменить роль пользователя (только админ)
app.put('/api/admin/users/:id/role', adminMiddleware, async (req, res) => {
    try {
        const { id } = req.params;
        const { role } = req.body;
        if (!['user', 'admin', 'moderator'].includes(role)) {
            return res.status(400).json({ error: 'Недопустимая роль' });
        }

        // Защита от изменения своей роли
        if (id == req.user.userId) {
            return res.status(400).json({ error: 'Нельзя изменить свою собственную роль' });
        }

        const result = await query(
            'UPDATE users SET role = $1 WHERE id_user = $2 RETURNING id_user, first_name, last_name, email, role',
            [role, id]
        );
        if (!result.rows[0]) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }
        res.json({ message: 'Роль обновлена', user: result.rows[0] });
    } catch (error) {
        console.error('Update role error:', error);
        res.status(500).json({ error: 'Ошибка обновления роли' });
    }
});

// ============================================
// API ADMIN: ТОВАРЫ
// ============================================
// Создать товар (только админ)
app.post('/api/admin/products',
    adminMiddleware,
    upload.single('image'),
    async (req, res) => {
        try {
            // Извлечение данных из запроса
            const { name, price, description, id_category, id_brand, features, img_url } = req.body;
            if (!name || !price) {
                return res.status(400).json({ error: 'Название и цена обязательны' });
            }

            // Определение приоритета изображения
            let finalImgUrl = img_url || null;
            if (req.file) {
                const fileName = req.file.originalname;
                finalImgUrl = `https://hehzsmgorxpkuozsrsjd.supabase.co/storage/v1/object/public/products/${fileName}`;
            }

            const result = await query(
                `INSERT INTO products (name, price, description, id_category, id_brand, img_url, features)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *`,
                [
                    name,
                    price,
                    description || '',
                    id_category || null,
                    id_brand || null,
                    finalImgUrl,
                    features ? JSON.stringify(features) : '[]'
                ]
            );
            res.status(201).json({
                message: 'Товар создан',
                product: result.rows[0]
            });
        } catch (error) {
            console.error('Create product error:', error);
            res.status(500).json({
                error: 'Ошибка создания товара',
                details: process.env.NODE_ENV === 'development' ? error.message : undefined
            });
        }
    });

// Получить все товары (только админ)
app.get('/api/admin/products', adminMiddleware, async (req, res) => {
    try {
        console.log('Admin fetching all products...');
        const startTime = Date.now();
        const result = await query(`
SELECT
p.*,
c.name as category_name,
b.name as brand_name
FROM products p
LEFT JOIN categories c ON p.id_category = c.id_category
LEFT JOIN brands b ON p.id_brand = b.id_brand
ORDER BY p.id_product DESC
`);
        console.log(`Loaded ${result.rows.length} products in ${Date.now() - startTime}ms`);
        res.json(result.rows);
    } catch (error) {
        console.error('Get products (admin) error:', error);
        res.status(500).json({
            error: 'Ошибка получения товаров',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// Обновить товар (только админ)
app.put('/api/admin/products/:id', adminMiddleware, upload.single('image'), async (req, res) => {
    try {
        const { id } = req.params;
        const { name, price, description, id_category, id_brand, features, img_url } = req.body;

        // Проверка существования товара
        const checkResult = await query('SELECT id_product, img_url FROM products WHERE id_product = $1', [id]);
        if (!checkResult.rows[0]) return res.status(404).json({ error: 'Товар не найден' });

        // Логика обновления изображения
        let finalImgUrl = img_url || checkResult.rows[0].img_url;
        if (req.file) {
            const fileName = req.file.originalname;
            finalImgUrl = `https://hehzsmgorxpkuozsrsjd.supabase.co/storage/v1/object/public/products/${fileName}`;
        }

        const result = await query(
            `UPDATE products SET name = COALESCE($1, name), price = COALESCE($2, price),
description = COALESCE($3, description), id_category = COALESCE(NULLIF($4, '')::int, id_category),
id_brand = COALESCE(NULLIF($5, '')::int, id_brand), img_url = COALESCE($6, img_url),
features = COALESCE($7::jsonb, features), updated_at = NOW()
WHERE id_product = $8 RETURNING *`,
            [name, price, description, id_category, id_brand, finalImgUrl, features ? JSON.stringify(features) : null, id]
        );
        res.json({ message: 'Товар обновлён', product: result.rows[0] });
    } catch (error) {
        console.error('Update product error:', error);
        res.status(500).json({ error: 'Ошибка обновления товара' });
    }
});

// Удалить товар (только админ)
app.delete('/api/admin/products/:id', adminMiddleware, async (req, res) => {
    try {
        const { id } = req.params;
        await query('DELETE FROM products WHERE id_product = $1', [id]);
        console.log('Product deleted:', id);
        res.json({ message: 'Товар удалён' });
    } catch (error) {
        console.error('Delete product error:', error);
        res.status(500).json({ error: 'Ошибка удаления товара' });
    }
});

// ============================================
// API ADMIN: ЗАКАЗЫ
// ============================================
// Получить все заказы (только админ)
app.get('/api/admin/orders', adminMiddleware, async (req, res) => {
    try {
        console.log('Fetching orders...');
        const result = await query(
            `SELECT
o.id_order,
o.total_amount as total,
o.status,
o.created_at,
u.id_user,
u.first_name || ' ' || u.last_name as user_name,
u.email
FROM orders o
LEFT JOIN users u ON o.id_user = u.id_user
ORDER BY o.created_at DESC`
        );
        console.log(`Loaded ${result.rows.length} orders`);
        res.json(result.rows);
    } catch (error) {
        console.error('Get orders error:', error);
        res.status(500).json({
            error: 'Ошибка получения заказов',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// Обновить статус заказа (только админ)
app.put('/api/admin/orders/:id/status', adminMiddleware, async (req, res) => {
    try {
        const { id } = req.params;
        const { status } = req.body;
        if (!['pending', 'processing', 'shipped', 'completed', 'cancelled'].includes(status)) {
            return res.status(400).json({ error: 'Недопустимый статус' });
        }
        const result = await query(
            'UPDATE orders SET status = $1 WHERE id_order = $2 RETURNING *',
            [status, id]
        );
        if (!result.rows[0]) {
            return res.status(404).json({ error: 'Заказ не найден' });
        }
        console.log('Order status updated:', result.rows[0]);
        res.json({ message: 'Статус обновлён', order: result.rows[0] });
    } catch (error) {
        console.error('Update order status error:', error);
        res.status(500).json({
            error: 'Ошибка обновления статуса',
            details: error.message
        });
    }
});

// ============================================
// AUTH ROUTES
// ============================================
app.post('/api/auth/register', async (req, res) => {
    try {
        console.log('Registration attempt:', req.body.email);
        const { firstName, lastName, email, password } = req.body;
        if (!firstName || !lastName || !email || !password) {
            return res.status(400).json({ error: 'Все поля обязательны' });
        }

        const existing = await query(
            'SELECT id_user FROM users WHERE email = $1',
            [email]
        );
        if (existing.rows.length > 0) {
            return res.status(400).json({ error: 'Пользователь с таким email уже существует' });
        }

        const passwordHash = await bcrypt.hash(password, 10);
        const result = await query(
            `INSERT INTO users (first_name, last_name, email, password_hash, role, avatar_url)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id_user, first_name, last_name, email, avatar_url, role`,
            [firstName, lastName, email, passwordHash, 'user', 'https://hehzsmgorxpkuozsrsjd.supabase.co/storage/v1/object/public/avatars/default.webp']
        );
        const user = result.rows[0];
        console.log('User created:', user.email);

        const token = jwt.sign(
            { userId: user.id_user, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: '7d' }
        );
        res.status(201).json({
            user: {
                id: user.id_user,
                firstName: user.first_name,
                lastName: user.last_name,
                email: user.email,
                avatar: user.avatar_url,
                role: user.role
            },
            token,
            message: 'Регистрация успешна'
        });
    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ error: 'Введите email и пароль' });
        }
        const result = await query(
            'SELECT * FROM users WHERE email = $1',
            [email]
        );
        const user = result.rows[0];
        if (!user) {
            return res.status(401).json({ error: 'Неверный email или пароль' });
        }
        const isValid = await bcrypt.compare(password, user.password_hash);
        if (!isValid) {
            return res.status(401).json({ error: 'Неверный email или пароль' });
        }
        const token = jwt.sign(
            { userId: user.id_user, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: '7d' }
        );
        delete user.password_hash;
        res.json({
            user: {
                id: user.id_user,
                firstName: user.first_name,
                lastName: user.last_name,
                email: user.email,
                avatar: user.avatar_url,
                role: user.role
            },
            token,
            message: 'Успешный вход'
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
    try {
        const result = await query(
            'SELECT id_user, first_name, last_name, email, avatar_url, role FROM users WHERE id_user = $1',
            [req.user.userId]
        );
        const user = result.rows[0];
        if (!user) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }
        res.json({
            user: {
                id: user.id_user,
                firstName: user.first_name,
                lastName: user.last_name,
                email: user.email,
                avatar: user.avatar_url,
                role: user.role
            }
        });
    } catch (error) {
        console.error('Get user error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/auth/logout', authMiddleware, async (req, res) => {
    res.json({ message: 'Выход выполнен' });
});

// ============================================
// API: ОТЗЫВЫ
// ============================================
// Получить все отзывы для товара
app.get('/api/products/:productId/reviews', async (req, res) => {
    try {
        const { productId } = req.params;
        const reviews = await query(
            `SELECT
r.*,
u.first_name,
u.last_name,
u.avatar_url
FROM reviews r
LEFT JOIN users u ON r.id_user = u.id_user
WHERE r.id_product = $1
ORDER BY r.created_at DESC`,
            [productId]
        );
        res.json(reviews.rows || []);
    } catch (error) {
        console.error('Get reviews error:', error);
        res.status(500).json({ error: 'Ошибка получения отзывов' });
    }
});

// Создать отзыв (только для авторизованных)
app.post('/api/products/:productId/reviews', authMiddleware, async (req, res) => {
    try {
        const { productId } = req.params;
        const { rating, comment } = req.body;
        const userId = req.user.userId;

        // Валидация данных
        if (!rating || rating < 1 || rating > 5) {
            return res.status(400).json({ error: 'Рейтинг должен быть от 1 до 5' });
        }
        if (!comment || comment.trim().length < 10) {
            return res.status(400).json({ error: 'Отзыв должен содержать минимум 10 символов' });
        }

        // Проверка дубликатов отзыва
        const existing = await query(
            'SELECT id_reviews FROM reviews WHERE id_product = $1 AND id_user = $2',
            [productId, userId]
        );
        if (existing.rows && existing.rows.length > 0) {
            return res.status(400).json({ error: 'Вы уже оставляли отзыв на этот товар' });
        }

        // Создание отзыва
        const result = await query(
            `INSERT INTO reviews (id_product, id_user, rating, comment)
VALUES ($1, $2, $3, $4)
RETURNING *`,
            [productId, userId, rating, comment]
        );
        const newReview = result.rows[0];

        // Получение данных пользователя
        const userResult = await query(
            'SELECT first_name, last_name, avatar_url FROM users WHERE id_user = $1',
            [userId]
        );
        const reviewWithUser = {
            ...newReview,
            first_name: userResult.rows[0]?.first_name || 'Аноним',
            avatar_url: userResult.rows[0]?.avatar_url
        };
        res.status(201).json(reviewWithUser);
    } catch (error) {
        console.error('Create review error:', error);
        res.status(500).json({ error: 'Ошибка создания отзыва' });
    }
});

// Обновить отзыв (только свой)
app.put('/api/reviews/:reviewId', authMiddleware, async (req, res) => {
    try {
        const { reviewId } = req.params;
        const { rating, comment } = req.body;
        const userId = req.user.userId;
        console.log('Update review:', { reviewId, userId, rating, comment });

        // Проверка прав владельца
        const ownerCheck = await query(
            'SELECT id_user FROM reviews WHERE id_reviews = $1',
            [reviewId]
        );
        if (!ownerCheck.rows || ownerCheck.rows.length === 0) {
            return res.status(404).json({ error: 'Отзыв не найден' });
        }
        if (ownerCheck.rows[0].id_user !== userId) {
            return res.status(403).json({ error: 'Нет прав для редактирования этого отзыва' });
        }

        // Обновление отзыва
        const result = await query(
            `UPDATE reviews
SET rating = $1,
comment = $2,
updated_at = NOW()
WHERE id_reviews = $3 AND id_user = $4
RETURNING *`,
            [rating, comment, reviewId, userId]
        );
        console.log('Review updated:', result.rows[0]);
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Update review error:', error);
        console.error('Error details:', error.message);
        res.status(500).json({
            error: 'Ошибка обновления отзыва',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// Удалить отзыв (только свой)
app.delete('/api/reviews/:reviewId', authMiddleware, async (req, res) => {
    try {
        const { reviewId } = req.params;
        const userId = req.user.userId;

        // Проверка прав владельца
        const ownerCheck = await query(
            'SELECT id_user FROM reviews WHERE id_reviews = $1',
            [reviewId]
        );
        if (!ownerCheck.rows[0] || ownerCheck.rows[0].id_user !== userId) {
            return res.status(403).json({ error: 'Нет прав для удаления этого отзыва' });
        }

        await query('DELETE FROM reviews WHERE id_reviews = $1', [reviewId]);
        res.json({ message: 'Отзыв удалён' });
    } catch (error) {
        console.error('Delete review error:', error);
        res.status(500).json({ error: 'Ошибка удаления отзыва' });
    }
});

// ============================================
// PROFILE UPDATE ROUTES
// ============================================
// Загрузка аватарки в Supabase Storage
app.post('/api/auth/avatar', authMiddleware, async (req, res) => {
    try {
        console.log('Avatar upload request');
        const { avatarData } = req.body;
        if (!avatarData) {
            return res.status(400).json({ error: 'Нет данных изображения' });
        }

        // Парсинг base64
        const matches = avatarData.match(/^data:([A-Za-z-+/]+);base64,(.+)$/);
        if (!matches || matches.length !== 3) {
            console.error('Invalid base64 format');
            return res.status(400).json({ error: 'Неверный формат изображения' });
        }
        const buffer = Buffer.from(matches[2], 'base64');
        const mimeType = matches[1];
        const fileExtension = mimeType.split('/')[1];

        // Санитизация userId
        const safeUserId = String(req.user.userId).replace(/[^a-zA-Z0-9_-]/g, '_');
        const fileName = `${safeUserId}/avatar.${fileExtension}`;
        console.log('Uploading:', fileName, 'Size:', buffer.length, 'bytes');

        // Проверка размера (5MB)
        if (buffer.length > 5 * 1024 * 1024) {
            return res.status(400).json({ error: 'Файл слишком большой (макс. 5MB)' });
        }

        // Загрузка через административный клиент (обход RLS)
        const { data, error: uploadError } = await supabaseAdmin.storage
            .from('avatars')
            .upload(fileName, buffer, {
                contentType: mimeType,
                upsert: true,
                cacheControl: '3600'
            });

        if (uploadError) {
            console.error('Supabase upload error:', uploadError);
            return res.status(500).json({
                error: 'Ошибка загрузки',
                details: uploadError.message
            });
        }
        console.log('File uploaded:', data);

        // Получение публичного URL
        const { urlData } = supabasePublic.storage
            .from('avatars')
            .getPublicUrl(fileName);
        let publicUrl = urlData?.publicUrl;
        if (!publicUrl) {
            const baseUrl = process.env.SUPABASE_URL.replace(/\/$/, '');
            publicUrl = `${baseUrl}/storage/v1/object/public/avatars/${fileName}`;
            console.log('Using fallback URL:', publicUrl);
        }
        console.log('Public URL:', publicUrl);

        // Обновление avatar_url в таблице users
        const updateResult = await query(
            'UPDATE users SET avatar_url = $1, updated_at = NOW() WHERE id_user = $2',
            [publicUrl, req.user.userId]
        );
        console.log('DB update result:', updateResult.rowCount, 'rows affected');
        if (updateResult.rowCount === 0) {
            console.warn('No rows updated - user not found');
            return res.status(404).json({ error: 'Пользователь не найден' });
        }
        res.json({
            success: true,
            avatarUrl: publicUrl,
            message: 'Аватарка обновлена'
        });
    } catch (error) {
        console.error('Avatar upload error:', error);
        console.error('Stack:', error.stack);
        res.status(500).json({
            error: 'Внутренняя ошибка сервера',
            message: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// Обновление профиля (имя, фамилия, email)
app.put('/api/auth/profile', authMiddleware, async (req, res) => {
    try {
        console.log('Profile update request:', req.body);
        const { firstName, lastName, email } = req.body;

        // Проверка email на уникальность
        if (email) {
            const existing = await query(
                'SELECT id_user FROM users WHERE email = $1 AND id_user != $2',
                [email, req.user.userId]
            );
            if (existing.rows.length > 0) {
                return res.status(400).json({ error: 'Email уже занят' });
            }
        }

        // Формирование запроса обновления
        const updates = [];
        const params = [];
        let paramIndex = 1;
        if (firstName) {
            updates.push(`first_name = $${paramIndex++}`);
            params.push(firstName);
        }
        if (lastName) {
            updates.push(`last_name = $${paramIndex++}`);
            params.push(lastName);
        }
        if (email) {
            updates.push(`email = $${paramIndex++}`);
            params.push(email);
        }
        if (updates.length === 0) {
            return res.status(400).json({ error: 'Нет данных для обновления' });
        }
        updates.push(`updated_at = NOW()`);
        params.push(req.user.userId);

        const result = await query(
            `UPDATE users
SET ${updates.join(', ')}
WHERE id_user = $${paramIndex}
RETURNING id_user, first_name, last_name, email, avatar_url, role`,
            params
        );
        const user = result.rows[0];
        console.log('Profile updated:', user.email);
        res.json({
            user: {
                id: user.id_user,
                firstName: user.first_name,
                lastName: user.last_name,
                email: user.email,
                avatar: user.avatar_url,
                role: user.role
            },
            message: 'Профиль обновлён'
        });
    } catch (error) {
        console.error('Profile update error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Смена пароля
app.put('/api/auth/password', authMiddleware, async (req, res) => {
    try {
        console.log('Password change request');
        const { currentPassword, newPassword } = req.body;
        if (!currentPassword || !newPassword) {
            return res.status(400).json({ error: 'Заполните все поля' });
        }
        if (newPassword.length < 6) {
            return res.status(400).json({ error: 'Пароль должен быть минимум 6 символов' });
        }

        // Проверка текущего пароля
        const result = await query(
            'SELECT password_hash FROM users WHERE id_user = $1',
            [req.user.userId]
        );
        const user = result.rows[0];
        if (!user) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }
        const isValid = await bcrypt.compare(currentPassword, user.password_hash);
        if (!isValid) {
            return res.status(401).json({ error: 'Неверный текущий пароль' });
        }

        // Хеширование нового пароля
        const passwordHash = await bcrypt.hash(newPassword, 10);
        await query(
            'UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id_user = $2',
            [passwordHash, req.user.userId]
        );
        console.log('Password changed for user:', req.user.userId);
        res.json({ message: 'Пароль успешно изменён' });
    } catch (error) {
        console.error('Password change error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// PRODUCTS ROUTES
// ============================================
app.get('/api/products', async (req, res) => {
    try {
        console.log('Getting products, pool stats:', getPoolStats());
        const { category, brand, minPrice, maxPrice, search } = req.query;
        console.log('Filters received:', { category, brand, minPrice, maxPrice, search });

        let queryText = `
SELECT p.*, b.name as brand_name, c.name as category_name
FROM products p
LEFT JOIN brands b ON p.id_brand = b.id_brand
LEFT JOIN categories c ON p.id_category = c.id_category
WHERE 1=1
`;
        const params = [];
        let paramIndex = 1;

        // Поддержка нескольких категорий
        if (category) {
            const categories = Array.isArray(category) ? category : [category];
            console.log('Filtering by categories:', categories);
            const placeholders = categories.map((_, i) => `$${paramIndex + i}`).join(', ');
            queryText += ` AND c.name IN (${placeholders})`;
            params.push(...categories);
            paramIndex += categories.length;
        }

        // Поддержка нескольких брендов
        if (brand) {
            const brands = Array.isArray(brand) ? brand : [brand];
            console.log('Filtering by brands:', brands);
            const placeholders = brands.map((_, i) => `$${paramIndex + i}`).join(', ');
            queryText += ` AND b.name IN (${placeholders})`;
            params.push(...brands);
            paramIndex += brands.length;
        }

        if (minPrice) {
            queryText += ` AND p.price >= $${paramIndex++}`;
            params.push(minPrice);
        }
        if (maxPrice) {
            queryText += ` AND p.price <= $${paramIndex++}`;
            params.push(maxPrice);
        }
        if (search) {
            queryText += ` AND (p.name ILIKE $${paramIndex} OR p.description ILIKE $${paramIndex})`;
            params.push(`%${search}%`);
            paramIndex++;
        }
        queryText += ' ORDER BY p.id_product';
        console.log('SQL Query:', queryText);
        console.log('SQL Params:', params);

        const result = await query(queryText, params);
        console.log('Products returned:', result.rows.length);
        res.json(result.rows);
    } catch (error) {
        console.error('Products error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/products/:id', async (req, res) => {
    try {
        console.log('Getting product:', req.params.id);
        const startTime = Date.now();
        const result = await query(`
SELECT p.*, b.name as brand_name, c.name as category_name
FROM products p
LEFT JOIN brands b ON p.id_brand = b.id_brand
LEFT JOIN categories c ON p.id_category = c.id_category
WHERE p.id_product = $1
`, [req.params.id]);
        console.log(`Query took ${Date.now() - startTime}ms`);
        console.log('Product result:', result.rows);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Товар не найден' });
        }
        const product = result.rows[0];
        product.reviews = [];
        res.json(product);
    } catch (error) {
        console.error('Product error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// CATEGORIES & BRANDS
// ============================================
app.get('/api/categories', async (req, res) => {
    try {
        const result = await query('SELECT * FROM categories ORDER BY id_category');
        res.json(result.rows);
    } catch (error) {
        console.error('Categories error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/brands', async (req, res) => {
    try {
        const result = await query('SELECT * FROM brands ORDER BY id_brand');
        res.json(result.rows);
    } catch (error) {
        console.error('Brands error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// CART ROUTES
// ============================================
app.get('/api/cart', authMiddleware, async (req, res) => {
    try {
        console.log('Fetching cart for user:', req.user.userId);
        const startTime = Date.now();
        const result = await query(`
SELECT ci.*, p.name, p.price, p.img_url
FROM cart_items ci
JOIN products p ON ci.id_product = p.id_product
WHERE ci.id_user = $1
ORDER BY ci.id_cart_items
`, [req.user.userId]);
        console.log(`Cart loaded in ${Date.now() - startTime}ms, ${result.rows.length} items`);

        const items = result.rows;
        const total = items.reduce((sum, item) => sum + (item.price * item.quantity), 0);
        res.json({ items, total });
    } catch (error) {
        console.error('Get cart error:', error);
        console.error('Error stack:', error.stack);
        res.status(500).json({
            error: 'Ошибка загрузки корзины',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

app.post('/api/cart', authMiddleware, async (req, res) => {
    const startTime = Date.now();
    console.log('[CART] Request started');
    try {
        const { productId, quantity = 1 } = req.body;
        console.log(`[CART] Adding product ${productId} (qty: ${quantity}) for user ${req.user.userId}`);

        if (!productId) {
            console.log('[CART] productId is required');
            return res.status(400).json({ error: 'productId обязателен' });
        }

        // Проверка товара
        const productCheckStart = Date.now();
        const productResult = await query(
            'SELECT id_product, price FROM products WHERE id_product = $1',
            [productId]
        );
        console.log(`[CART] Product check: ${Date.now() - productCheckStart}ms`);
        if (productResult.rows.length === 0) {
            console.log('[CART] Product not found');
            return res.status(404).json({ error: 'Товар не найден' });
        }

        // Проверка существующего элемента
        const existingCheckStart = Date.now();
        const existingResult = await query(
            'SELECT * FROM cart_items WHERE id_user = $1 AND id_product = $2',
            [req.user.userId, productId]
        );
        console.log(`[CART] Existing check: ${Date.now() - existingCheckStart}ms`);

        if (existingResult.rows.length > 0) {
            const newQuantity = existingResult.rows[0].quantity + quantity;
            const updateStart = Date.now();
            await query(
                'UPDATE cart_items SET quantity = $1 WHERE id_user = $2 AND id_product = $3',
                [newQuantity, req.user.userId, productId]
            );
            console.log(`[CART] Update: ${Date.now() - updateStart}ms`);
            console.log('[CART] Item updated');
        } else {
            const insertStart = Date.now();
            await query(
                'INSERT INTO cart_items (id_user, id_product, quantity) VALUES ($1, $2, $3)',
                [req.user.userId, productId, quantity]
            );
            console.log(`[CART] Insert: ${Date.now() - insertStart}ms`);
            console.log('[CART] Item inserted');
        }
        const totalTime = Date.now() - startTime;
        console.log(`[CART] Completed in ${totalTime}ms`);
        res.json({ message: 'Товар добавлен в корзину' });
    } catch (error) {
        console.error('[CART] Error:', error.message);
        console.log(`[CART] Failed in ${Date.now() - startTime}ms`);
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/cart/:productId', authMiddleware, async (req, res) => {
    try {
        const { quantity } = req.body;
        await query(
            'UPDATE cart_items SET quantity = $1 WHERE id_user = $2 AND id_product = $3',
            [quantity, req.user.userId, req.params.productId]
        );
        res.json({ message: 'Корзина обновлена' });
    } catch (error) {
        console.error('Update cart error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/cart/:productId', authMiddleware, async (req, res) => {
    try {
        await query(
            'DELETE FROM cart_items WHERE id_user = $1 AND id_product = $2',
            [req.user.userId, req.params.productId]
        );
        res.json({ message: 'Товар удалён из корзины' });
    } catch (error) {
        console.error('Delete cart error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/cart', authMiddleware, async (req, res) => {
    try {
        await query(
            'DELETE FROM cart_items WHERE id_user = $1',
            [req.user.userId]
        );
        res.json({ message: 'Корзина очищена' });
    } catch (error) {
        console.error('Clear cart error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// ORDERS ROUTES
// ============================================
app.post('/api/orders', authMiddleware, async (req, res) => {
    try {
        const { totalAmount, shippingAddress, items } = req.body;
        if (!totalAmount || !shippingAddress || !items || items.length === 0) {
            return res.status(400).json({ error: 'Все поля обязательны' });
        }

        const orderResult = await query(
            `INSERT INTO orders (id_user, total_amount, shipping_address, status)
VALUES ($1, $2, $3, $4)
RETURNING *`,
            [req.user.userId, totalAmount, shippingAddress, 'pending']
        );
        const order = orderResult.rows[0];

        for (const item of items) {
            await query(
                `INSERT INTO order_items (id_order, id_product, product_name, price_at_purchase, quantity, subtotal)
VALUES ($1, $2, $3, $4, $5, $6)`,
                [order.id_order, item.productId, item.name, item.price, item.quantity, item.subtotal]
            );
        }

        await query(
            'DELETE FROM cart_items WHERE id_user = $1',
            [req.user.userId]
        );
        res.status(201).json({ message: 'Заказ создан', order });
    } catch (error) {
        console.error('Create order error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/orders', authMiddleware, async (req, res) => {
    try {
        const result = await query(
            `SELECT o.*,
json_agg(json_build_object(
'productId', oi.id_product,
'name', oi.product_name,
'price', oi.price_at_purchase,
'qty', oi.quantity,
'subtotal', oi.subtotal,
'img_url', p.img_url
)) as items
FROM orders o
LEFT JOIN order_items oi ON o.id_order = oi.id_order
LEFT JOIN products p ON oi.id_product = p.id_product
WHERE o.id_user = $1
GROUP BY o.id_order
ORDER BY o.created_at DESC`,
            [req.user.userId]
        );
        res.json(result.rows);
    } catch (error) {
        console.error('Get orders error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/orders/:id', authMiddleware, async (req, res) => {
    try {
        const result = await query(
            `SELECT o.*,
json_agg(json_build_object(
'productId', oi.id_product,
'name', oi.product_name,
'price', oi.price_at_purchase,
'qty', oi.quantity,
'subtotal', oi.subtotal
)) as items
FROM orders o
LEFT JOIN order_items oi ON o.id_order = oi.id_order
WHERE o.id_order = $1 AND o.id_user = $2
GROUP BY o.id_order`,
            [req.params.id, req.user.userId]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Заказ не найден' });
        }
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Get order error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// СТАТИСТИКА ПУЛА СОЕДИНЕНИЙ
// ============================================
app.get('/api/pool-stats', (req, res) => {
    res.json(getPoolStats());
});

// Endpoint для проверки и очистки пула
app.get('/api/admin/pool', (req, res) => {
    const stats = getPoolStats();
    res.json({
        message: 'Pool statistics',
        stats,
        tip: 'Use POST to restart server if pool is stuck'
    });
});

app.post('/api/admin/restart', (req, res) => {
    console.log('Restart requested...');
    res.json({ message: 'Server restarting in 2 seconds...' });
    setTimeout(() => {
        process.exit(0);
    }, 2000);
});

// Endpoint для принудительной очистки пула
app.post('/api/admin/clear-pool', async (req, res) => {
    console.log('Clearing pool...');
    try {
        await pool.end();
        console.log('Pool ended');
        res.json({ message: 'Pool cleared and recreated' });
    } catch (error) {
        console.error('Failed to clear pool:', error);
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// ГЛОБАЛЬНЫЙ ОБРАБОТЧИК ОШИБОК EXPRESS
// ============================================
app.use((err, req, res, next) => {
    console.error('Express error handler:', err);
    res.status(500).json({
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});

// ============================================
// ГЛОБАЛЬНЫЕ ОБРАБОТЧИКИ NODE.JS
// ============================================
process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err.message);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection:', reason);
});

// Graceful shutdown
process.on('SIGINT', async () => {
    console.log('SIGINT received, shutting down gracefully...');
    await pool.end();
    process.exit(0);
});

process.on('SIGTERM', async () => {
    console.log('SIGTERM received, shutting down gracefully...');
    await pool.end();
    process.exit(0);
});

// ============================================
// ЗАПУСК СЕРВЕРА
// ============================================
const startServer = async () => {
    try {
        console.log('Checking database connection...');
        const connected = await checkConnection();
        if (!connected) {
            console.error('Cannot connect to database. Exiting...');
            process.exit(1);
        }
        app.listen(PORT, () => {
            console.log(`Server running on http://localhost:${PORT}`);
            console.log(`API: http://localhost:${PORT}/api`);
            console.log(`Database: Connected to Supabase`);
            console.log(`Pool stats:`, getPoolStats());
        });
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
};

startServer();