const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');

const app = express();

app.use(cors());
app.use(express.json());

const port = 3000;

const db = new sqlite3.Database('./yemekapp.db', (err) => {
    if (err) {
        console.error("DB bağlantı hatası:", err.message);
    } else {
        console.log("DB bağlantısı başarılı.");
        initializeDb();
    }
});

function ifErrLog(tableName) {
    return (err) => {
        if (err) console.error(`${tableName} oluşturma/kontrol hatası:`, err.message);
    };
}

function initializeDb() {
    db.serialize(() => {
        // Users Table
        db.run(`
          CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            address TEXT DEFAULT '',
            role TEXT DEFAULT 'customer' NOT NULL CHECK(role IN ('customer', 'restaurant_owner', 'admin', 'courier'))
          )
        `, (err) => {
            ifErrLog("Users tablosu")(err);
            // Add 'address' column if it doesn't exist (for backward compatibility if old DB exists)
            db.all("PRAGMA table_info(users)", (pragmaErr, columns) => {
                if (pragmaErr) { console.error("Users tablo PRAGMA hatası:", pragmaErr); return; }
                if (columns && !columns.some(col => col.name === 'address')) {
                    db.run("ALTER TABLE users ADD COLUMN address TEXT DEFAULT ''",
                        (alterErr) => { if (alterErr) console.error("Users 'address' ekleme hatası:", alterErr); else console.log("'address' users tablosuna eklendi."); }
                    );
                }
            });
        });

        // Restaurants Table
        db.run(`
          CREATE TABLE IF NOT EXISTS restaurants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            address TEXT,
            category TEXT,
            description TEXT,
            image_url TEXT,
            owner_id INTEGER,
            FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE SET NULL
          )
        `, (err) => {
            ifErrLog("Restaurants tablosu")(err);
             db.all("PRAGMA table_info(restaurants)", (pragmaErr, columns) => {
                if (pragmaErr) { console.error("Restaurants tablo PRAGMA hatası:", pragmaErr); return;}
                if (columns && columns.length > 0) {
                    const hasOwnerIdColumn = columns.some(col => col.name === 'owner_id');
                    if (!hasOwnerIdColumn) {
                        db.run("ALTER TABLE restaurants ADD COLUMN owner_id INTEGER REFERENCES users(id) ON DELETE SET NULL",
                            (alterErr) => { if (alterErr) console.error("Restaurants 'owner_id' ekleme hatası:", alterErr); else console.log("'owner_id' restaurants tablosuna eklendi."); }
                        );
                    }
                }
            });
        });

        // Menus Table
        db.run(`
          CREATE TABLE IF NOT EXISTS menus (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            restaurant_id INTEGER,
            name TEXT NOT NULL,
            description TEXT,
            price REAL NOT NULL,
            category TEXT,
            image_url TEXT,
            FOREIGN KEY (restaurant_id) REFERENCES restaurants(id) ON DELETE CASCADE
          )
        `, ifErrLog("Menus tablosu"));

        // Orders Table
        db.run(`
          CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER, /* Can be NULL if user is deleted */
            restaurant_id INTEGER, /* Can be NULL if restaurant is deleted */
            total_price REAL NOT NULL,
            status TEXT NOT NULL DEFAULT 'hazırlanıyor', /* Türkçe karakterler sorun çıkarabilir, 'hazirlaniyor' daha güvenli */
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
            FOREIGN KEY (restaurant_id) REFERENCES restaurants(id) ON DELETE SET NULL
          )
        `, ifErrLog("Orders tablosu"));

        // Order_items Table
        db.run(`
          CREATE TABLE IF NOT EXISTS order_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id INTEGER NOT NULL,
            menu_id INTEGER, /* Can be NULL if menu item is deleted */
            quantity INTEGER NOT NULL,
            price REAL NOT NULL,
            FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
            FOREIGN KEY (menu_id) REFERENCES menus(id) ON DELETE SET NULL
          )
        `, (err) => {
            ifErrLog("Order_items tablosu")(err);
            checkAndInsertSampleData(); // Sample data insertion after all tables are set up
        });
    });
}

async function hashPassword(password) {
    return bcrypt.hash(password, 10);
}

async function insertUserIfNotExists(userData) {
    return new Promise((resolve, reject) => {
        db.get("SELECT id FROM users WHERE email = ?", [userData.email], async (err, user) => {
            if (err) {
                console.error(`${userData.role} '${userData.email}' kontrol hatası:`, err.message);
                return reject(err);
            }
            if (user) {
                // console.log(`Mevcut ${userData.role} (${userData.email}) bulundu. ID: ${user.id}.`);
                return resolve(user.id);
            }
            try {
                const hashedPassword = await hashPassword(userData.password);
                db.run("INSERT INTO users (name, email, password, role, address) VALUES (?, ?, ?, ?, ?)",
                    [userData.name, userData.email, hashedPassword, userData.role, userData.address || ''],
                    function(insertErr) {
                        if (insertErr) {
                            console.error(`${userData.role} '${userData.email}' ekleme hatası:`, insertErr.message);
                            reject(insertErr);
                        } else {
                            console.log(`${userData.role} (${userData.email}) eklendi. ID: ${this.lastID}.`);
                            resolve(this.lastID);
                        }
                    }
                );
            } catch (hashErr) {
                console.error(`${userData.role} '${userData.email}' şifre hashleme hatası:`, hashErr);
                reject(hashErr);
            }
        });
    });
}

const sampleRestaurantsAndMenusData = [
    {
        restaurant: { name: "Burger King", email_owner: "burgerking@gmail.com", address: "Beşiktaş, İstanbul", category: "Fast Food", description: "Alevde ızgara hamburger keyfi!", image_url: "https://upload.wikimedia.org/wikipedia/commons/thumb/c/cc/Burger_King_2020.svg/940px-Burger_King_2020.svg.png" },
        menus: [
            { name: "Whopper Menü", description: "Efsane Whopper, orta boy patates ve içecek.", price: 280.00, category: "Menüler", image_url: "https://www.burgerking.com.tr/cmsfiles/products/whopper-menu.webp?v=690" },
            { name: "King Chicken Menü", description: "King Chicken, orta boy patates ve içecek.", price: 250.00, category: "Menüler", image_url: "https://www.burgerking.com.tr/cmsfiles/products/king-chicken-menu.webp?v=690" },
        ]
    },
    {
        restaurant: { name: "McDonald's", email_owner: "mcdonalds@gmail.com", address: "Kadıköy, İstanbul", category: "Fast Food", description: "I'm lovin' it!", image_url: "https://upload.wikimedia.org/wikipedia/commons/thumb/3/36/McDonald%27s_Golden_Arches.svg/240px-McDonald%27s_Golden_Arches.svg.png" },
        menus: [
            { name: "Big Mac Menü", description: "İkonik Big Mac, orta boy patates ve içecek.", price: 275.00, category: "Menüler", image_url: "https://images.deliveryhero.io/image/fd-tr/Products/10770272.jpg??width=800" },
            { name: "McChicken Menü", description: "Lezzetli McChicken, orta boy patates ve içecek.", price: 240.00, category: "Menüler", image_url: "https://images.deliveryhero.io/image/fd-tr/Products/10770273.jpg??width=800" },
        ]
    },
    {
        restaurant: { name: "Popeyes", email_owner: "popeyes@gmail.com", address: "Şişli, İstanbul", category: "Fast Food", description: "Louisiana Mutfağı!", image_url: "https://upload.wikimedia.org/wikipedia/commons/thumb/1/1f/Popeyes_logo.svg/220px-Popeyes_logo.svg.png" },
        menus: [
            { name: "Acılı Kanat Menü", description: "Acılı kanatlar, patates ve içecek.", price: 260.00, category: "Menüler", image_url: "https://www.popeyes.com.tr/cmsfiles/products/11-li-kanat-menu-1.png?v=690" },
        ]
    },
     {
        restaurant: { name: "Starbucks", email_owner: "starbucks@gmail.com", address: "Nişantaşı, İstanbul", category: "Kafe", description: "Kahve ve daha fazlası.", image_url: "https://upload.wikimedia.org/wikipedia/tr/thumb/2/26/Starbucks_Coffee.svg/220px-Starbucks_Coffee.svg.png" },
        menus: [
            { name: "Caffe Latte (Grande)", description: "Espresso ve buharlaştırılmış süt.", price: 120.00, category: "Kahveler", image_url: "https://globalassets.starbucks.com/assets/b635f407bbcd49e7b8dd9119ce33f769.jpg?impolicy=1by1_tight_288" },
            { name: "Cool Lime (Grande)", description: "Serinletici lime ve nane.", price: 110.00, category: "Soğuk İçecekler", image_url: "https://globalassets.starbucks.com/assets/211011f479f2466c9898815c95c0c6a9.jpg?impolicy=1by1_tight_288" },
        ]
    },
    { // Generic restaurant linked to restaurant@example.com
        restaurant: { name: "Örnek Restoran", email_owner: "restaurant@example.com", address: "Merkez, Ankara", category: "Türk Mutfağı", description: "Lezzetli yemekler burada!", image_url: "https://via.placeholder.com/300x160.png?text=Örnek+Restoran" },
        menus: [
            { name: "Adana Kebap", description: "Acılı, közlenmiş domates ve biber ile.", price: 250.00, category: "Kebaplar", image_url: "https://via.placeholder.com/150x100.png?text=Adana" },
            { name: "Mercimek Çorbası", description: "Sıcak ve doyurucu.", price: 80.00, category: "Çorbalar", image_url: "https://via.placeholder.com/150x100.png?text=Çorba" },
        ]
    }
];

async function addSampleData() {
    console.log("Örnek kullanıcılar ve restoranlar ekleniyor/kontrol ediliyor...");

    // Default Users
    const usersToCreate = [
        { name: "Ana Admin", email: "admin@example.com", password: "admin123", role: "admin", address: "Admin Merkezi" },
        { name: "Restoran Sahibi Ana", email: "restaurant@example.com", password: "password123", role: "restaurant_owner", address: "Sahip Adresi 1" },
        { name: "Kurye Ali", email: "courier@example.com", password: "courier123", role: "courier", address: "Kurye Dağıtım Noktası" },
        { name: "Burger King Sahibi", email: "burgerking@gmail.com", password: "123456", role: "restaurant_owner", address: "BK Genel Merkez"},
        { name: "McDonald's Sahibi", email: "mcdonalds@gmail.com", password: "123456", role: "restaurant_owner", address: "McD Genel Merkez"},
        { name: "Popeyes Sahibi", email: "popeyes@gmail.com", password: "123456", role: "restaurant_owner", address: "Popeyes Genel Merkez"},
        { name: "Starbucks Sahibi", email: "starbucks@gmail.com", password: "123456", role: "restaurant_owner", address: "Starbucks Genel Merkez"}
    ];

    const ownerEmailToIdMap = {};

    for (const userData of usersToCreate) {
        try {
            const userId = await insertUserIfNotExists(userData);
            if (userData.role === 'restaurant_owner') {
                ownerEmailToIdMap[userData.email] = userId;
            }
        } catch (err) {
            // Error already logged in insertUserIfNotExists
        }
    }
     console.log("Kullanıcı ekleme/kontrol işlemi tamamlandı.");

    // Restaurants and Menus
    for (const data of sampleRestaurantsAndMenusData) {
        const r = data.restaurant;
        const ownerId = ownerEmailToIdMap[r.email_owner];

        if (!ownerId) {
            console.warn(`Restoran '${r.name}' için sahip (${r.email_owner}) bulunamadı veya oluşturulamadı. Restoran eklenemiyor.`);
            continue;
        }

        // Check if restaurant exists for this owner
        const existingRestaurant = await new Promise((resolve, reject) => {
            db.get("SELECT id FROM restaurants WHERE name = ? AND owner_id = ?", [r.name, ownerId], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });

        let restaurantId;
        if (existingRestaurant) {
            restaurantId = existingRestaurant.id;
            // console.log(`Mevcut restoran bulundu: ${r.name} (ID: ${restaurantId})`);
        } else {
            restaurantId = await new Promise((resolve, reject) => {
                const restaurantSql = "INSERT INTO restaurants (name, address, category, description, image_url, owner_id) VALUES (?, ?, ?, ?, ?, ?)";
                db.run(restaurantSql, [r.name, r.address, r.category, r.description, r.image_url, ownerId], function(restaurantErr) {
                    if (restaurantErr) {
                        console.error(`Restoran eklenirken hata (${r.name}):`, restaurantErr.message);
                        reject(restaurantErr);
                    } else {
                        console.log(`Restoran eklendi: ${r.name} (ID: ${this.lastID}, Sahip ID: ${ownerId})`);
                        resolve(this.lastID);
                    }
                });
            });
        }

        if (restaurantId && data.menus && data.menus.length > 0) {
            const menuSql = "INSERT INTO menus (restaurant_id, name, description, price, category, image_url) VALUES (?, ?, ?, ?, ?, ?)";
            for (const m of data.menus) {
                // Check if menu item exists for this restaurant
                const existingMenu = await new Promise((resolve, reject) => {
                    db.get("SELECT id FROM menus WHERE name = ? AND restaurant_id = ?", [m.name, restaurantId], (err, row) => {
                        if(err) reject(err);
                        else resolve(row);
                    });
                });

                if (existingMenu) {
                    // console.log(`  -> Mevcut menü öğesi: ${m.name} (Rest. ID: ${restaurantId})`);
                } else {
                    await new Promise((resolveMenu) => { // Renamed inner resolve
                        db.run(menuSql, [restaurantId, m.name, m.description, m.price, m.category, m.image_url], (menuErr) => {
                            if (menuErr) console.error(`  Menü öğesi eklenirken hata (${m.name} - R.ID: ${restaurantId}):`, menuErr.message);
                            else console.log(`  -> Menü öğesi eklendi: ${m.name} (R.ID: ${restaurantId})`);
                            resolveMenu();
                        });
                    });
                }
            }
        } else if (restaurantId) {
            // console.log(`  -> ${r.name} için menü öğesi bulunmuyor veya zaten eklendi.`);
        }
    }
    console.log("Tüm örnek verilerin eklenmesi/kontrolü tamamlandı.");
}


function checkAndInsertSampleData() {
    db.get("SELECT COUNT(*) as count FROM users WHERE role='admin'", (err, row) => { // Check for an admin to decide if sample data is needed
        if (err) {
            console.error("Admin sayısı kontrol hatası:", err.message);
            return;
        }
        if (row.count === 0) { // If no admin, likely a fresh DB
            console.log("Veritabanı boş görünüyor (admin yok), örnek veriler ekleniyor...");
            addSampleData();
        } else {
            console.log("Veritabanında admin kullanıcısı var, örnek veri ekleme süreci (addSampleData) yalnızca eksikleri tamamlayacak.");
            addSampleData(); // Still call it to add missing restaurant owners or restaurants if any
        }
    });
}


// --- ENDPOINTS ---

// LOGIN
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email ve şifre gereklidir.' });
  }
  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err) {
        console.error("Login DB error:", err.message);
        return res.status(500).json({ error: 'Sunucu hatası.' });
    }
    if (!user) return res.status(400).json({ error: 'Kullanıcı bulunamadı veya e-posta yanlış.' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: 'Şifre yanlış.' });

    res.json({ message: 'Giriş başarılı.', userId: user.id, name: user.name, role: user.role });
  });
});

// REGISTER
app.post('/register', async (req, res) => {
  const { name, email, password, role } = req.body;
  if (!name || !email || !password) {
      return res.status(400).json({ error: 'Tüm alanlar zorunludur.' });
  }
  if (password.length < 6) {
      return res.status(400).json({ error: 'Şifre en az 6 karakter olmalıdır.' });
  }

  const userRole = role || 'customer';
  const validRoles = ['customer', 'courier']; // Publicly registerable roles
  if (role && !validRoles.includes(userRole)) { // Only validate if role is provided and not in allowed list
      return res.status(400).json({ error: `Geçersiz kullanıcı rolü. Sadece ${validRoles.join(', ')} rolleriyle kayıt olunabilir.` });
  }
  if (userRole === 'restaurant_owner' || userRole === 'admin') { // Explicitly block these roles from public registration
        return res.status(400).json({ error: `Bu rol (${userRole}) ile genel kayıt yapılamaz.` });
  }


  try {
    const hashedPassword = await hashPassword(password);
    db.run('INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)',
      [name, email, hashedPassword, userRole],
      function(err) {
        if (err) {
          if (err.message.includes('UNIQUE constraint failed: users.email')) {
            return res.status(400).json({ error: 'Bu e-posta adresi zaten kayıtlı.' });
          }
          console.error("Kayıt sırasında DB hatası:", err.message);
          return res.status(500).json({ error: 'Kullanıcı oluşturulamadı.' });
        }
        res.status(201).json({ message: 'Kullanıcı başarıyla kayıt oldu.', userId: this.lastID });
      }
    );
  } catch (err) {
    console.error("Kayıt sırasında genel hata:", err);
    res.status(500).json({ error: 'Sunucu hatası.' });
  }
});

// PROFILE
app.get('/profile/:userId', (req, res) => {
    const userId = req.params.userId;
    db.get('SELECT id, name, email, address, role FROM users WHERE id = ?', [userId], (err, user) => {
        if (err) return res.status(500).json({ error: 'Sunucu hatası.' });
        if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı.' });
        res.json(user);
    });
});

app.put('/profile/:userId', (req, res) => {
    const userId = req.params.userId;
    const { name, email, address } = req.body;

    if (!name && !email && address === undefined) {
        return res.status(400).json({ error: 'Güncellenecek en az bir alan gönderilmelidir.' });
    }

    let updates = [];
    let params = [];
    if (name) { updates.push('name = ?'); params.push(name); }
    if (email) { updates.push('email = ?'); params.push(email); }
    if (address !== undefined) { updates.push('address = ?'); params.push(address); }

    if (updates.length === 0) { // Should not happen due to initial check but good practice
        return res.status(400).json({ error: 'Güncellenecek geçerli bir alan bulunamadı.' });
    }
    params.push(userId);

    const query = `UPDATE users SET ${updates.join(', ')} WHERE id = ?`;
    db.run(query, params, function(err) {
        if (err) {
            if (err.message.includes('UNIQUE constraint failed: users.email')) {
                return res.status(400).json({ error: 'Bu e-posta adresi zaten kullanımda.' });
            }
            return res.status(500).json({ error: 'Kullanıcı bilgileri güncellenemedi.' });
        }
        if (this.changes === 0) return res.status(404).json({ error: 'Kullanıcı bulunamadı.' });

        db.get('SELECT id, name, email, address, role FROM users WHERE id = ?', [userId], (err, updatedUser) => {
            if (err) return res.status(500).json({ error: 'Güncellenmiş kullanıcı bilgileri alınamadı.' });
            res.json({ message: 'Kullanıcı bilgileri güncellendi.', user: updatedUser });
        });
    });
});

app.put('/profile/:userId/password', async (req, res) => {
    const userId = req.params.userId;
    const { oldPassword, newPassword } = req.body;

    if (!oldPassword || !newPassword) {
        return res.status(400).json({ error: 'Eski ve yeni şifre gereklidir.' });
    }
    if (newPassword.length < 6) {
        return res.status(400).json({ error: 'Yeni şifre en az 6 karakter olmalıdır.' });
    }

    db.get('SELECT password FROM users WHERE id = ?', [userId], async (err, user) => {
        if (err) return res.status(500).json({ error: 'Sunucu hatası.' });
        if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı.' });

        const match = await bcrypt.compare(oldPassword, user.password);
        if (!match) return res.status(400).json({ error: 'Eski şifre yanlış.' });

        try {
            const hashedNewPassword = await hashPassword(newPassword);
            db.run('UPDATE users SET password = ? WHERE id = ?', [hashedNewPassword, userId], function(err) {
                if (err) return res.status(500).json({ error: 'Şifre güncellenemedi.' });
                res.json({ message: 'Şifre başarıyla güncellendi.' });
            });
        } catch (hashErr) {
            res.status(500).json({ error: 'Şifre hashlenirken hata oluştu.' });
        }
    });
});

// --- AUTHORIZATION MIDDLEWARES ---
function authorizeRole(roles) {
    return (req, res, next) => {
        const userIdString = req.headers['user-id']; // Ensure frontend sends this
        if (!userIdString) return res.status(401).json({ error: 'Yetkilendirme başarısız: Kullanıcı ID başlığı eksik.' });

        const userId = parseInt(userIdString, 10);
        if (isNaN(userId)) return res.status(401).json({ error: 'Yetkilendirme başarısız: Geçersiz Kullanıcı ID formatı.' });

        db.get('SELECT role FROM users WHERE id = ?', [userId], (err, user) => {
            if (err) {
                console.error("Role Auth DB Error:", err.message);
                return res.status(500).json({ error: 'Yetkilendirme sırasında sunucu hatası.' });
            }
            if (!user) return res.status(401).json({ error: 'Yetkilendirme başarısız: Kullanıcı bulunamadı.' });
            if (!roles.includes(user.role)) return res.status(403).json({ error: 'Yetkisiz erişim: Gerekli role sahip değilsiniz.' });

            req.user = user; // Attach user role to request object
            req.userId = userId; // Attach userId to request object
            next();
        });
    };
}
// Specific authorization for order status updates by owner or admin
function authorizeOrderStatusUpdate(req, res, next) {
    const userId = req.userId; // Set by authorizeRole
    const userRole = req.user.role; // Set by authorizeRole
    const orderIdParamString = req.params.orderId;
    const newStatus = req.body.status ? req.body.status.toLowerCase() : null;

    if (!newStatus) return res.status(400).json({ error: "Yeni durum (status) gerekli."});
    if (!orderIdParamString) return res.status(400).json({ error: "Sipariş ID'si gerekli." });

    const orderId = parseInt(orderIdParamString, 10);
    if (isNaN(orderId)) return res.status(400).json({ error: 'Geçersiz sipariş ID formatı.' });

    db.get('SELECT restaurant_id, status FROM orders WHERE id = ?', [orderId], (err, order) => {
        if (err) { console.error("Order Status Auth DB Error:", err.message); return res.status(500).json({ error: 'Sipariş bilgisi alınırken hata.' });}
        if (!order) return res.status(404).json({ error: 'Sipariş bulunamadı.' });

        if (userRole === 'admin') return next(); // Admin can do anything

        if (userRole === 'restaurant_owner') {
            db.get('SELECT owner_id FROM restaurants WHERE id = ?', [order.restaurant_id], (rErr, restaurant) => {
                if (rErr) return res.status(500).json({ error: 'Restoran sahibi kontrolünde hata.' });
                if (!restaurant || restaurant.owner_id !== userId) {
                    return res.status(403).json({ error: 'Yetkisiz erişim: Bu siparişin restoranına sahip değilsiniz.' });
                }
                // Restaurant owner can change status to 'hazırlanıyor', 'kuryeye verildi', 'iptal edildi'
                const allowedOwnerStatuses = ['hazırlanıyor', 'kuryeye verildi', 'iptal edildi'];
                if (!allowedOwnerStatuses.includes(newStatus)) {
                    return res.status(403).json({ error: `Restoran sahibi siparişi '${newStatus}' durumuna güncelleyemez.` });
                }
                return next();
            });
        } else { // This middleware isn't for couriers changing status. They have their own endpoint.
            return res.status(403).json({ error: 'Yetkisiz erişim.' });
        }
    });
}


// --- ADMIN ENDPOINTS ---
app.get('/admin/users', authorizeRole(['admin']), (req, res) => {
    db.all('SELECT id, name, email, role, address FROM users ORDER BY id DESC', [], (err, users) => {
        if (err) { console.error("Admin - Kullanıcı listeleme hatası:", err.message); return res.status(500).json({ error: "Kullanıcılar listelenirken bir hata oluştu." });}
        res.json(users);
    });
});

app.get('/admin/restaurants', authorizeRole(['admin']), (req, res) => {
    const query = `
        SELECT r.id, r.name, r.address, r.category, r.description, r.image_url, r.owner_id, u.name as owner_name
        FROM restaurants r
        LEFT JOIN users u ON r.owner_id = u.id
        ORDER BY r.id DESC
    `;
    db.all(query, [], (err, restaurants) => {
        if (err) { console.error("Admin - Restoran listeleme hatası:", err.message); return res.status(500).json({ error: "Restoranlar listelenirken bir hata oluştu." });}
        res.json(restaurants);
    });
});

app.get('/admin/all-orders', authorizeRole(['admin']), (req, res) => {
  const { userIdParam, status, startDate, endDate, restaurantId } = req.query;
  let query = `
    SELECT o.id as orderId, o.status, o.total_price, o.created_at,
           r.name as restaurant_name, u.name as user_name, u.email as user_email
    FROM orders o
    LEFT JOIN restaurants r ON o.restaurant_id = r.id
    LEFT JOIN users u ON o.user_id = u.id
    WHERE 1=1
  `;
  const params = [];

  if (userIdParam) { query += ' AND o.user_id = ?'; params.push(userIdParam); }
  if (restaurantId) { query += ' AND o.restaurant_id = ?'; params.push(restaurantId); }
  if (status) { query += ' AND o.status = ?'; params.push(status.toLowerCase()); }
  if (startDate) { query += ' AND o.created_at >= ?'; params.push(startDate + ' 00:00:00'); } // Include whole day
  if (endDate) { query += ' AND o.created_at <= ?'; params.push(endDate + ' 23:59:59'); }   // Include whole day

  query += ' ORDER BY o.created_at DESC';

  db.all(query, params, (err, rows) => {
    if (err) { console.error("Admin - Tüm siparişleri alırken hata:", err.message); return res.status(500).json({ error: 'Siparişler alınamadı.' });}
    res.json(rows);
  });
});


// --- RESTAURANT OWNER ENDPOINTS ---
app.get('/my-restaurants', authorizeRole(['restaurant_owner']), (req, res) => {
    db.all('SELECT * FROM restaurants WHERE owner_id = ? ORDER BY name', [req.userId], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Restoranlarınız alınamadı.' });
        res.json(rows);
    });
});

app.get('/restaurant-panel/orders/:restaurantId', authorizeRole(['restaurant_owner']), (req, res) => {
    const restaurantId = req.params.restaurantId;
    // First, verify this owner actually owns this restaurant
    db.get('SELECT owner_id FROM restaurants WHERE id = ?', [restaurantId], (err, restaurant) => {
        if (err) return res.status(500).json({ error: "Restoran kontrolünde hata."});
        if (!restaurant) return res.status(404).json({ error: "Restoran bulunamadı."});
        if (restaurant.owner_id !== req.userId) return res.status(403).json({error: "Bu restorana erişim yetkiniz yok."});

        // If authorized, get orders for this restaurant
        db.all(`
            SELECT o.id as orderId, o.status, o.total_price, o.created_at,
                   u.name as customer_name, u.address as customer_address, u.email as customer_email
            FROM orders o
            JOIN users u ON o.user_id = u.id
            WHERE o.restaurant_id = ?
            ORDER BY o.created_at DESC
        `, [restaurantId], (err, orders) => {
            if (err) { console.error("Restoran paneli siparişleri alınırken hata:", err.message); return res.status(500).json({ error: 'Siparişler alınamadı.' });}
            if (orders.length === 0) return res.json([]);

            const orderIds = orders.map(o => o.orderId);
            const placeholders = orderIds.map(() => '?').join(',');

            db.all(
            `SELECT oi.order_id, m.name as menu_name, m.image_url as menu_image_url, oi.quantity, oi.price
                FROM order_items oi
                JOIN menus m ON oi.menu_id = m.id
                WHERE oi.order_id IN (${placeholders})`,
            orderIds,
            (err, orderItems) => {
                if (err) return res.status(500).json({ error: 'Sipariş detayları alınamadı.' });
                const ordersWithDetails = orders.map(order => ({
                    ...order,
                    items: orderItems.filter(item => item.order_id === order.orderId)
                }));
                res.json(ordersWithDetails);
            });
        });
    });
});

// --- COURIER ENDPOINTS ---
// Courier specific authorization (slightly different from general role auth if needed, but can reuse authorizeRole)
function authorizeCourier(req, res, next) {
    const userIdString = req.headers['user-id'];
    if (!userIdString) return res.status(401).json({ error: 'User ID gerekli.' });
    const userId = parseInt(userIdString, 10);

    db.get('SELECT role FROM users WHERE id = ?', [userId], (err, user) => {
      if (err) return res.status(500).json({ error: 'Sunucu hatası.' });
      if (!user || user.role !== 'courier') return res.status(403).json({ error: 'Yetkisiz erişim. Kurye rolü gerekli.' });
      req.userId = userId; // Add userId for consistency if needed by other parts
      next();
    });
}

app.get('/courier/orders', authorizeCourier, (req, res) => {
    const sql = `
      SELECT o.id, o.status, o.total_price, r.name AS restaurant_name, u.address AS delivery_address, o.created_at
      FROM orders o
      JOIN restaurants r ON o.restaurant_id = r.id
      JOIN users u ON o.user_id = u.id
      WHERE o.status = 'kuryeye verildi' /* Assuming this is the status when assigned to a courier */
      ORDER BY o.created_at ASC
    `;
    db.all(sql, [], (err, rows) => {
      if (err) {
        console.error("Kurye siparişleri alınırken hata:", err.message);
        return res.status(500).json({ error: 'Siparişler alınamadı.' });
      }
      res.json(rows);
    });
});

app.put('/courier/order/:orderId/delivered', authorizeCourier, (req, res) => {
    const orderId = parseInt(req.params.orderId);
    if (isNaN(orderId)) return res.status(400).json({ error: 'Geçersiz sipariş ID.' });

    // Courier can only mark 'kuryeye verildi' orders as 'teslim edildi'
    const sql = "UPDATE orders SET status = 'teslim edildi' WHERE id = ? AND status = 'kuryeye verildi'";
    db.run(sql, [orderId], function(err) {
      if (err) {
        console.error("Kurye sipariş güncelleme hatası:", err.message);
        return res.status(500).json({ error: 'Sipariş güncellenemedi.' });
      }
      if (this.changes === 0) return res.status(404).json({ error: 'Sipariş bulunamadı veya durumu kurye tarafından güncellenmeye uygun değil.' });
      res.json({ message: 'Sipariş teslim edildi olarak güncellendi.' });
    });
});


// --- ORDER STATUS UPDATE (Used by Admin, Restaurant Owner) ---
app.put('/order/:orderId/status', authorizeRole(['admin', 'restaurant_owner']), authorizeOrderStatusUpdate, (req, res) => {
  const orderId = req.params.orderId;
  const { status } = req.body;

  if (!status) return res.status(400).json({ error: "Yeni durum (status) gereklidir."});

  db.run('UPDATE orders SET status = ? WHERE id = ?', [status.toLowerCase(), orderId], function (err) {
      if (err) {
          console.error("Order status update error:", err.message);
          return res.status(500).json({ error: 'Sipariş durumu güncellenemedi.' });
      }
      if (this.changes === 0) return res.status(404).json({ error: 'Sipariş bulunamadı veya durum zaten aynı.' });
      res.json({ message: `Sipariş durumu başarıyla '${status}' olarak güncellendi.` });
    }
  );
});


// --- ADD RESTAURANT/MENU (Protected) ---
app.post('/add-restaurant', authorizeRole(['admin', 'restaurant_owner']), (req, res) => {
  const { name, address, category, description, image_url } = req.body;
  let ownerIdToSet = req.userId; // By default, the logged-in user

  // If admin is adding, they can specify an owner_id
  if (req.user.role === 'admin' && req.body.owner_id) {
      ownerIdToSet = parseInt(req.body.owner_id);
      if(isNaN(ownerIdToSet)) return res.status(400).json({ error: "Admin için geçerli bir owner_id gönderilmedi."});
      // Optional: Check if owner_id exists and is a restaurant_owner
  }

  if (!name) return res.status(400).json({ error: 'Restoran adı gerekli.' });

  db.run(
    'INSERT INTO restaurants (name, address, category, description, image_url, owner_id) VALUES (?, ?, ?, ?, ?, ?)',
    [name, address, category, description, image_url, ownerIdToSet],
    function (err) {
      if (err) { console.error("Restoran ekleme hatası:", err.message); return res.status(500).json({ error: 'Restoran eklenemedi.' });}
      res.status(201).json({ message: 'Restoran başarıyla eklendi.', restaurantId: this.lastID, ownerId: ownerIdToSet });
    }
  );
});

app.post('/add-menu-item', authorizeRole(['restaurant_owner', 'admin']), (req, res) => {
  const { restaurant_id, name, description, price, category, image_url } = req.body;
  const currentUserId = req.userId; // from authorizeRole middleware

  if (!restaurant_id || !name || price == null) {
      return res.status(400).json({ error: 'Restoran ID, menü adı ve fiyat zorunludur.' });
  }
  if (isNaN(parseFloat(price)) || parseFloat(price) < 0) {
      return res.status(400).json({ error: 'Geçersiz fiyat değeri.' });
  }


  // Check if the user is authorized to add menu to this restaurant
  db.get("SELECT owner_id FROM restaurants WHERE id = ?", [restaurant_id], (err, restaurant) => {
    if (err) { console.error("Menü eklerken restoran kontrol hatası:", err.message); return res.status(500).json({error: "Restoran kontrolünde hata."});}
    if (!restaurant) return res.status(404).json({error: "Restoran bulunamadı."});

    // If user is restaurant_owner, they must own this restaurant
    if (req.user.role === 'restaurant_owner' && restaurant.owner_id !== currentUserId) {
        return res.status(403).json({error: "Bu restorana menü ekleme yetkiniz yok."});
    }
    // Admin can add to any restaurant (already checked by authorizeRole)

    db.run(
        'INSERT INTO menus (restaurant_id, name, description, price, category, image_url) VALUES (?, ?, ?, ?, ?, ?)',
        [restaurant_id, name, description, parseFloat(price), category, image_url],
        function (err) {
          if (err) { console.error("Menü ekleme hatası:", err.message); return res.status(500).json({ error: 'Menü öğesi eklenemedi.' });}
          res.status(201).json({ message: 'Menü öğesi başarıyla eklendi.', menuItemId: this.lastID });
        }
      );
  });
});


// --- PUBLIC ENDPOINTS ---
app.get('/restaurants', (req, res) => {
  const searchTerm = req.query.search;
  let query = 'SELECT * FROM restaurants';
  const params = [];

  if (searchTerm) {
    query += ' WHERE name LIKE ? OR category LIKE ? OR description LIKE ?';
    const likeTerm = `%${searchTerm}%`;
    params.push(likeTerm, likeTerm, likeTerm);
  }
  query += ' ORDER BY name';

  db.all(query, params, (err, rows) => {
    if (err) { console.error("Restoran arama/listeleme hatası:", err.message); return res.status(500).json({ error: 'Restoranlar alınamadı.' });}
    res.json(rows);
  });
});

app.get('/menu/:restaurantId', (req, res) => {
  const restaurantId = req.params.restaurantId;
  if (isNaN(parseInt(restaurantId))) return res.status(400).json({error: "Geçersiz restoran ID."})
  db.all('SELECT * FROM menus WHERE restaurant_id = ? ORDER BY category, name', [restaurantId], (err, rows) => {
    if (err) { console.error(`Menü yükleme hatası (R.ID: ${restaurantId}):`, err.message); return res.status(500).json({ error: 'Menü öğeleri alınamadı.' });}
    res.json(rows);
  });
});

app.get('/menu-items/search', (req, res) => {
    const searchTerm = req.query.q;
    if (!searchTerm) return res.status(400).json({ error: "Arama terimi 'q' gereklidir." });

    const likeTerm = `%${searchTerm}%`;
    const query = `
        SELECT m.id as menu_id, m.name as menu_name, m.description as menu_description, m.price as menu_price, m.category as menu_category, m.image_url as menu_image_url,
               r.id as restaurant_id, r.name as restaurant_name, r.image_url as restaurant_image_url
        FROM menus m
        JOIN restaurants r ON m.restaurant_id = r.id
        WHERE m.name LIKE ? OR m.description LIKE ? OR m.category LIKE ? OR r.name LIKE ?
        ORDER BY r.name, m.name
    `;
    db.all(query, [likeTerm, likeTerm, likeTerm, likeTerm], (err, rows) => {
        if (err) { console.error("Yemek arama hatası:", err.message); return res.status(500).json({ error: 'Yemekler aranırken bir hata oluştu.' });}
        res.json(rows);
    });
});

app.post('/order', (req, res) => {
  const { userId, restaurantId, items } = req.body;

  if (!userId || !restaurantId || !items || !Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'Eksik veya hatalı sipariş verisi.' });
  }
  if (isNaN(parseInt(userId)) || isNaN(parseInt(restaurantId))) {
      return res.status(400).json({error: "Geçersiz kullanıcı veya restoran ID."});
  }

  const menuIds = items.map(i => i.menuId);
  if (menuIds.some(id => id === undefined || id === null || isNaN(parseInt(id)))) {
    return res.status(400).json({ error: 'Sipariş öğelerinde geçersiz menuId bulundu.' });
  }

  const placeholders = menuIds.map(() => '?').join(',');
  db.all(`SELECT id, price FROM menus WHERE id IN (${placeholders})`, menuIds, (err, menuRows) => {
    if (err) return res.status(500).json({ error: 'Menü bilgileri alınırken sunucu hatası.' });

    const foundMenuIds = menuRows.map(m => m.id);
    const notFoundIds = menuIds.filter(id => !foundMenuIds.includes(id));
    if (notFoundIds.length > 0) {
      return res.status(400).json({ error: `Şu menü öğeleri bulunamadı: ${notFoundIds.join(', ')}` });
    }

    let totalPrice = 0;
    for (const item of items) {
      const menuItem = menuRows.find(m => m.id === item.menuId);
      if (!menuItem) return res.status(400).json({ error: `Menu item ID ${item.menuId} bulunamadı.`}); // Should be caught above
      if (item.quantity === undefined || isNaN(parseInt(item.quantity)) || parseInt(item.quantity) <= 0) {
        return res.status(400).json({ error: `Menu ID ${item.menuId} için geçersiz miktar.` });
      }
      totalPrice += menuItem.price * item.quantity;
    }

    db.run('INSERT INTO orders (user_id, restaurant_id, total_price, status) VALUES (?, ?, ?, ?)',
      [userId, restaurantId, totalPrice, 'hazırlanıyor'], // Default status
      function(err) {
        if (err) { console.error("Sipariş ekleme hatası:", err.message); return res.status(500).json({ error: 'Sipariş oluşturulamadı.' });}
        const orderId = this.lastID;

        const stmt = db.prepare('INSERT INTO order_items (order_id, menu_id, quantity, price) VALUES (?, ?, ?, ?)');
        items.forEach(item => {
          const menuItem = menuRows.find(m => m.id === item.menuId);
          stmt.run(orderId, item.menuId, item.quantity, menuItem.price);
        });
        stmt.finalize((finalizeErr) => {
            if (finalizeErr) {
                console.error("Sipariş detayları eklenirken hata:", finalizeErr);
                // Attempt to rollback or delete the order if items fail to insert
                db.run("DELETE FROM orders WHERE id = ?", [orderId], (delErr) => {
                    if(delErr) console.error("Sipariş geri alma hatası:", delErr.message);
                });
                return res.status(500).json({ error: 'Sipariş detayları eklenirken hata oluştu.' });
            }
            res.status(201).json({ message: 'Sipariş başarıyla oluşturuldu.', orderId });
        });
      }
    );
  });
});

app.get('/orders/:userId', (req, res) => {
  const userId = req.params.userId;
  if (isNaN(parseInt(userId))) return res.status(400).json({error: "Geçersiz kullanıcı ID."});

  db.all(
    `SELECT o.id as orderId, o.status, o.total_price, o.created_at,
            r.name as restaurant_name, r.image_url as restaurant_image_url
     FROM orders o
     JOIN restaurants r ON o.restaurant_id = r.id
     WHERE o.user_id = ? ORDER BY o.created_at DESC`,
    [userId],
    (err, orders) => {
      if (err) return res.status(500).json({ error: 'Sunucu hatası (orders).' });
      if (orders.length === 0) return res.json([]);

      const orderIds = orders.map(o => o.orderId);
      const placeholders = orderIds.map(() => '?').join(',');

      db.all(
        `SELECT oi.order_id, m.name as menu_name, m.image_url as menu_image_url, oi.quantity, oi.price
         FROM order_items oi
         JOIN menus m ON oi.menu_id = m.id
         WHERE oi.order_id IN (${placeholders})`,
        orderIds,
        (err, orderItems) => {
          if (err) return res.status(500).json({ error: 'Sunucu hatası (order_items).' });
          const ordersWithItems = orders.map(order => ({
            ...order,
            items: orderItems.filter(item => item.order_id === order.orderId)
          }));
          res.json(ordersWithItems);
        }
      );
    }
  );
});


// SERVER LISTEN
app.listen(port, () => {
  console.log(`Sunucu çalışıyor: http://localhost:${port}`);
});