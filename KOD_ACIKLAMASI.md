# CSRF Savunma Mekanizmaları - Kod Açıklamaları

Aşağıda Banka Uygulaması'nın (`bank-app/server.js`) güvenlik önlemlerini nasıl uyguladığına dair detaylı kod açıklamalarını bulabilirsiniz.

## 1. Anti-CSRF Token Oluşturumu ve Kullanımı

### Token Nasıl Oluşturulur?
Anti-CSRF Token, kullanıcı sisteme giriş yaptığında oturum bazlı olarak (Session) sunucu tarafında rastgele bir metin (UUID) kullanılarak oluşturulur. Bu token sadece sunucuda saklanır ve kullanıcının sayfasına gömülür.

**Dosya: `bank-app/server.js`**
```javascript
// Generate CSRF Token Middleware
function generateCsrfToken(req, res, next) {
  // Eğer oturumda (session) henüz bir token yoksa, rastgele bir UUID oluştur
  if (!req.session.csrfToken) {
    req.session.csrfToken = uuidv4();
  }
  // Bu token'ı, kullanıcının göreceği HTML sayfasında (EJS) kullanabilmek için yerel değişkene ata
  res.locals.csrfToken = req.session.csrfToken;
  next();
}

// Token, dashboard sayfası yüklenirken "generateCsrfToken" fonksiyonu (middleware) çalıştırılarak oluşturulur
app.get('/dashboard', requireLogin, generateCsrfToken, (req, res) => { ... });
```

### Token ÖnYüzde (Frontend) Nasıl Kullanılır?
Form gönderilirken token gizli bir input olarak gönderilir.

**Dosya: `bank-app/views/dashboard.ejs`**
```html
<form action="/transfer-token" method="POST">
    <!-- CSRF Token gizli input olarak formda saklanıyor -->
    <input type="hidden" name="_csrf" value="<%= csrfToken %>">
    ...
</form>
```

### Token Sunucuda Nasıl Doğrulanır?
Form POST edildiğinde, sunucu gelen token ile kendi oturum belleğinde (session) sakladığı token'ın eşleşip eşleşmediğini kontrol eder.

**Dosya: `bank-app/server.js`**
```javascript
app.post('/transfer-token', requireLogin, (req, res) => {
  const { amount, to, _csrf } = req.body;
  
  // Gelen _csrf ile, Session'daki (Oturumdaki) csrfToken eşleşmiyorsa işlem reddedilir
  if (!_csrf || _csrf !== req.session.csrfToken) {
    return res.status(403).render('result', { 
      success: false, 
      message: 'CSRF Attack Blocked! Invalid or Missing Anti-CSRF Token.' 
    });
  }
  // Eşleşiyorsa transfere izin verilir
});
```

---

## 2. Custom Header (Özel Başlık) Savunması

Saldırganlar `<form>` tagı kullanarak kurbanın tarayıcısına zorla istek yaptırtabilir, fakat form isteklerine **Custom Header (Özel Başlık)** ekleyemezler. Özel başlık eklemek için JavaScript `fetch()` veya `XMLHttpRequest` kullanılmalıdır, bu da CORS (Cross-Origin Resource Sharing) kısıtlamalarına takılır.

**Dosya: `bank-app/server.js`**
```javascript
app.post('/transfer-header', requireLogin, (req, res) => {
  // Gelen istekte 'X-Requested-With' özel başlığı aranır
  const customHeader = req.headers['x-requested-with'];
  
  // Eğer başlık yoksa veya değeri 'XMLHttpRequest' değilse işlem engellenir
  if (customHeader !== 'XMLHttpRequest') {
    return res.status(403).render('result', { ... });
  }
});
```

---

## 3. Fetch Metadata Savunması

Modern tarayıcılar (Chrome, Firefox vs.) sunucuya yapılan isteklerin kaynağını belirtmek için ekstra Metadata başlıkları gönderir (`Sec-Fetch-Site`).

**Dosya: `bank-app/server.js`**
```javascript
app.post('/transfer-metadata', requireLogin, (req, res) => {
  // İstek başlıklarından sec-fetch-site değeri alınır
  const fetchSite = req.headers['sec-fetch-site'];
  
  // 'cross-site' değeri, bu isteğin bankanın kendi domaininden DEĞİL,
  // farklı bir kaynaktan (örn: attacker-site) tetiklendiğini gösterir
  if (fetchSite === 'cross-site') {
    return res.status(403).render('result', { ... });
  }
});
```

---

## 4. SameSite Cookies Savunması

Çerezlerin (Cookies) SameSite özelliği `Strict` veya `Lax` olarak ayarlandığında, tarayıcı bu çerezleri farklı domainlere (cross-site) yapılan isteklerde otomatik olarak eklemez. Çerez gitmediği için sunucu isteği anonim sayar ve işlemi reddeder.

**Dosya: `bank-app/server.js`** (Çerezin Oluşturulduğu Yer)
```javascript
app.post('/login', (req, res) => {
  // ... giriş başarılıysa ...
  // Özel bir SameSite=Strict cookie tanımlanıyor
  res.cookie('session_id_strict', 'strict-value-123', {
    httpOnly: true,
    sameSite: 'strict' // En katı SameSite ayarı, farklı siteden POST'larda asla gönderilmez!
  });
});
```

**Dosya: `bank-app/server.js`** (Korumanın Test Edildiği Yer)
```javascript
app.post('/transfer-samesite', requireLogin, (req, res) => {
  // Gelen istekte strict çerez var mı diye bakılıyor
  const strictCookie = req.cookies['session_id_strict'];
  
  // Saldırganın sitesinden yapılan form isteklerinde tarayıcı sameSite='strict' çerezini
  // eklemeyeceği için bu değer undefined gelir ve saldırı engellenir.
  if (!strictCookie || strictCookie !== 'strict-value-123') {
    return res.status(403).render('result', { ... });
  }
});
```
