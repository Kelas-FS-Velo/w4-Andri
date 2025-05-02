# w4-Andri

## Cara Menjalankan Project

### 1. Jalankan Frontend (FE)
Masuk ke folder `fe`, lalu jalankan:

```bash
npm install      # hanya pertama kali
npm run dev
```
Frontend akan berjalan di http://localhost:5173 (atau port lain sesuai output terminal).

### 2. Jalankan Backend (BE)
Masuk ke folder `be`, lalu jalankan:

```bash
php artisan serve
```
Backend akan berjalan di http://127.0.0.1:8000

---

**Catatan:**
- Pastikan Node.js & npm sudah ter-install untuk FE.
- Pastikan PHP & Composer sudah ter-install untuk BE (Laravel).
- Jalankan kedua perintah di dua terminal berbeda agar FE & BE aktif bersamaan.
