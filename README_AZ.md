# ELFA Marketplace — Satıcı təsdiq sistemi

Bu paket ELFA-nın mövcud müştəri səhifəsini saxlayır və əlavə edir:
- Satıcı qeydiyyatı (`seller-register.html`)
- Satıcı girişi və məhsul idarəetməsi (`seller-register.html`)
- Administrator girişi və satıcı təsdiqi (`admin.html`)
- FastAPI backend + Supabase PostgreSQL / yerli işlətmə üçün SQLite
- Yalnız təsdiqlənmiş satıcıların məhsullarını qaytaran public API (`/api/products`)

## Vercel-də yerləşdirmək

1. Layihə qovluğunu GitHub-a yüklə və Vercel-də repozitoriyanı import et. `main.py` FastAPI giriş faylıdır.
2. Supabase layihəsində **Connect** düyməsindən **Transaction pooler** bağlantı ünvanını götür. Vercel Environment Variables bölməsində həmin ünvanı `POSTGRES_URL` adı ilə əlavə et. Serverless işləmə üçün Transaction pooler istifadə olunur.
3. `ADMIN_TOKEN` adlı güclü, təsadüfi məxfi dəyər əlavə et. Onu `/admin.html` səhifəsində administrator girişi zamanı istifadə et.
4. İstəsən Preview mühitinə də bu dəyişənləri əlavə et və layihəni deploy et.

Backend ilk başladıqda cədvəlləri Supabase PostgreSQL bazasında avtomatik yaradır; SQL Editor-də ayrıca sorğu işlətməyə ehtiyac yoxdur. Deploy-dan sonra `/`, `/admin.html`, `/seller-register.html` və `/api/health` ünvanlarını yoxla. SQLite yalnız yerli işlətmə üçündür.

## Windows-da yerli işlətmək

1. Python 3.11 və ya daha yenisini quraşdır.
2. Qovluqda terminal aç, asılılıqları quraşdır, administrator tokenini təyin et və serveri başlat:

```bat
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
set ADMIN_TOKEN=BurayaGucluVeUnikalTokenYaz
py run.py
```

3. Brauzerdə aç:
- Müştəri saytı: `http://127.0.0.1:8000/`
- Satıcı qeydiyyatı və paneli: `http://127.0.0.1:8000/seller-register.html`
- Administrator paneli: `http://127.0.0.1:8000/admin.html`
- API yoxlaması: `http://127.0.0.1:8000/api/health`

## İş axını

1. Satıcı qeydiyyatdan keçir və statusu `pending` olur.
2. Satıcı panelinə daxil olanda “Təsdiq gözləyir” mesajını görür.
3. Administrator `/admin.html` səhifəsinə daxil olub satıcını təsdiqləyir və ya rədd edir.
4. Təsdiqlənmiş satıcı məhsul əlavə edə bilər.
5. Müştəri ana səhifəsindəki “Satıcı mağazalarından” bölməsində təsdiqlənmiş satıcıların məhsulları görünür.

## Vacib qeydlər

- `main.py` Vercel giriş nöqtəsidir, `run.py` isə yerli başlatma üçündür. Fayllar yükləmə zamanı `(2)` və `(3)` kimi əlavə adlar aldığı üçün backend uyğun səhifə fayllarını həmin adlarla tapır.

- `ADMIN_TOKEN`-u məxfi saxla və başqaları ilə paylaşma.
- Supabase Transaction pooler bağlantısı üçün `POSTGRES_URL` və ya `DATABASE_URL` qəbul edilir. Şifrədə `@`, `#` və ya boşluq varsa, onu bağlantı ünvanında URL-encode et.
- Satıcı şəkilləri üçün `R2_ACCOUNT_ID`, `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`, `R2_BUCKET` və `R2_PUBLIC_URL` dəyişənlərini də əlavə et. Bunlar qurulmayıbsa şəkillər PostgreSQL bazasında saxlanır.
- Bu başlanğıc versiyadır. İctimai yayımdan əvvəl HTTPS, server səviyyəsində rate limiting, ehtiyat nüsxə, e-poçt təsdiqi, şifrə sıfırlama, moderasiya qaydaları və təhlükəsizlik auditi əlavə edilməlidir.
- Mövcud ana səhifədəki nümunə məhsullar demo məzmunudur. Yeni satıcı məhsulları verilənlər bazasından ayrıca göstərilir.
- Sifariş, çatdırılma və ödənişin satıcılar arasında bölüşdürülməsi bu mərhələyə daxil deyil; növbəti mərhələdə ayrıca qurulmalıdır.
