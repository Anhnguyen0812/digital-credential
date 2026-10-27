# Văn bằng Học tập Số Tiết lộ Chọn lọc (W3C VC 2.0 & ECDSA-SD-2023)

Hệ thống cấp phát, lưu trữ và xác minh văn bằng số tự chủ theo chuẩn **W3C VC 2.0**, **ECDSA-SD-2023**, **Bitstring Status List v1.0** và **OpenID4VCI / OpenID4VP (DCQL)**.

## 1. Chạy nhanh bằng Docker

```powershell
docker compose up --build -d
```

| Phân hệ | Địa chỉ | Tài khoản mẫu |
| :--- | :--- | :--- |
| **1. Cổng Nhà trường** | `http://localhost:4001/issuer.html` | • Giáo vụ (`REGISTRAR`): `chuyenvien` / `ChuyenVien@2026`<br>• Trưởng phòng (`APPROVER`): `truongphong` / `TruongPhong@2026`<br>• Quản trị (`ADMIN`): `admin` / `Admin@2026` |
| **2. Ví Sinh viên** | `http://localhost:3000/wallet.html` | • SV đang học (SSO): `23020009@vnu.edu.vn` / `SinhVien@2026`<br>• Cựu SV mất mail (VNeID): CCCD `001193005566`, NS `1993-08-15`, OTP `246810` |
| **3. Cổng Tuyển dụng** | `http://localhost:4002/verifier.html` | • FPT Software: `hr.fpt` / `FptRecruit@2026`<br>• Viettel Cyber Security: `hr.viettel` / `ViettelSec@2026` |
| **4. Bàn Demo Hội đồng** | `http://localhost:3000/index.html` | Giao diện 3 cột & mô phỏng 5 kịch bản tấn công |

> **Lấy link HTTPS để quét QR bằng điện thoại:** `docker compose logs https-tunnel`

## 2. Chạy Local & Kiểm thử (Node.js >= 20)

```powershell
npm install
npm test              # Chạy 43 ca kiểm thử (6 tệp test)
npm run typecheck     # Kiểm tra kiểu TypeScript
npm start             # Chạy server tích hợp tại http://localhost:3000
npm run benchmark:final
```

## 3. Cấu trúc chính

```text
public/               # Giao diện Web (issuer.html, wallet.html, verifier.html, index.html)
src/
  auth/               # Băm mật khẩu scrypt, HttpOnly session cookie, LoginThrottle
  context/            # JSON-LD context nội bộ & offline documentLoader (did:web, did:key)
  crypto/             # Multikey P-256, Holder Binding 2 lớp, ký số sổ gốc & SVG Watermark
  profiles/           # Hồ sơ DegreeCredential & CourseCertificateCredential
  status/             # W3C Bitstring Status List (131.072 bits nén GZIP + ETag 304)
  infra/              # PostgreSQL 16 store & Redis 7 ReplayGuard (SET NX EX 300)
  portal/             # API nghiệp vụ 3 cổng (RBAC 4 mắt, OpenID4VCI PoP, Backup AES-256-GCM)
  services/           # Entrypoints cho 3 container (issuer, wallet, verifier)
tests/                # 43 bài kiểm thử tự động (Vitest)
```
