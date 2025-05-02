# Fitur Sistem Perpustakaan

## Daftar Isi
1. [Pendahuluan](#1-pendahuluan)
2. [Fitur Fungsional](#2-fitur-fungsional)
   - [2.1 Peminjaman Buku](#21-peminjaman-buku)
   - [2.2 Pelaporan](#22-pelaporan)
3. [Spesifikasi Proses Bisnis/Teknis/Fungsional](#3-spesifikasi-proses-bisnis-teknis-fungsional)
   - [3.1 Peminjaman Buku](#31-peminjaman-buku)
   - [3.2 Pelaporan](#32-pelaporan)
4. [Stakeholder & Hak Akses](#4-stakeholder--hak-akses)

## 1. Pendahuluan
Dokumen ini menjelaskan fitur utama yang tersedia pada sistem perpustakaan, bertujuan untuk meningkatkan efisiensi layanan dan kemudahan bagi anggota maupun admin.

## 2. Fitur Fungsional

### 2.1 Peminjaman Buku
- Anggota perpustakaan dapat memesan buku secara online.
- Sistem memungkinkan pengecekan ketersediaan buku secara real-time.
- Anggota akan menerima notifikasi saat buku siap diambil, sehingga mengurangi waktu tunggu.

### 2.2 Pelaporan
- Admin perpustakaan dapat menghasilkan laporan peminjaman harian, mingguan, dan bulanan.
- Laporan tersedia dalam format Excel dan PDF untuk memudahkan analisis dan audit.

## 3. Spesifikasi Proses Bisnis/Teknis/Fungsional

### 3.1 Peminjaman Buku

#### Alur Kerja
1. Pengguna login ke sistem.
2. Pengguna mencari buku yang diinginkan.
3. Sistem menampilkan status ketersediaan buku.
4. Pengguna mengajukan permintaan peminjaman.
5. Sistem melakukan validasi:
   - Jika buku tersedia: proses booking otomatis, dengan batas waktu pengambilan maksimal 3 hari.
   - Jika buku sedang dipinjam: pengguna masuk ke dalam antrean (waiting list).

#### Aturan Peminjaman
- Maksimal 3 buku per anggota secara bersamaan.
- Denda keterlambatan pengembalian: Rp 5.000 per hari.

### 3.2 Pelaporan

#### Parameter Laporan
- Data peminjaman: judul buku, nama anggota, tanggal pinjam dan tanggal kembali.
- Statistik: buku paling populer, tingkat keterlambatan pengembalian.

#### Format Laporan
- Ekspor ke PDF atau Excel.
- Tampilan grafik untuk visualisasi data.

## 4. Stakeholder & Hak Akses

Section ini menjelaskan siapa saja yang menggunakan fitur dan batasan peran/hak aksesnya pada sistem perpustakaan.

| Fitur             | Stakeholder | Hak Akses                                                                 |
|-------------------|-------------|--------------------------------------------------------------------------|
| Peminjaman Buku   | Anggota     | Lihat ketersediaan, ajukan peminjaman, lihat riwayat peminjaman           |
|                   | Admin       | Approve/reject peminjaman, atur denda                                    |
| Pelaporan         | Admin       | Generate laporan, unduh laporan, filter laporan                           |

- **Anggota**: Dapat melihat ketersediaan buku, melakukan peminjaman, dan memantau riwayat peminjaman.
- **Admin**: Memiliki kontrol penuh atas peminjaman (persetujuan, denda) dan pelaporan (pembuatan, pengunduhan, filter).