# PoC chứng chỉ số - Tuần 04

Repo này minh họa một luồng nhỏ: trường ký bằng tốt nghiệp, sinh viên chọn vài thuộc tính để chia sẻ và bên tuyển dụng xác minh lại.

## Công nghệ

- Node.js 20 trở lên, đã kiểm tra với Node.js 24
- TypeScript và pnpm
- W3C Verifiable Credentials Data Model 2.0
- ECDSA-SD-2023 của Digital Bazaar
- Vitest

Khóa P-256 được tạo mới trong RAM mỗi lần chạy. Repo không lưu private key.

## Cài đặt và chạy

```bash
pnpm install
pnpm test
pnpm demo
pnpm benchmark
```

Kiểm tra cả kiểu dữ liệu và test:

```bash
pnpm check
```

Sau khi chạy demo, ba file mẫu được sinh ra trong `.demo-output/`. Thư mục này đã nằm trong `.gitignore` vì proof và khóa thử nghiệm thay đổi ở mỗi lần chạy.

`pnpm benchmark` chạy khởi động 5 vòng rồi đo 30 vòng. Kết quả gồm min, median, p95, max của issue/disclose/verify và kích thước JSON. File kết quả nằm tại `.demo-output/benchmark.json`.

## Demo làm gì

1. Tạo khóa ECDSA P-256.
2. Tạo và ký một `DegreeCredential` theo VC 2.0.
3. Dẫn xuất credential chỉ còn `id`, họ tên, ngành học và trạng thái tốt nghiệp.
4. Xác minh base proof bằng confirm cryptosuite và derived proof bằng verify cryptosuite.
5. Kiểm tra nonce, audience và chặn nonce dùng lại.

Các trường `studentCode`, `degreeName`, `graduationDate`, `gpa` và `classification` không xuất hiện trong bản chia sẻ.

Ví dụ màn hình:

```text
=== WEEK 04 DEMO ===
Credential hop le: true
Cac truong duoc chia se: [ 'id', 'studentName', 'major', 'graduated' ]
GPA bi an: true
Presentation lan 1: true
Replay bi chan: true
```

## Các ca test

| Mã | Nội dung | Kết quả mong đợi |
|---|---|---|
| P1 | Ký và xác minh credential gốc | Thành công |
| P2 | Tiết lộ đúng các trường đã chọn | Trường riêng tư bị ẩn |
| P3 | Sửa ngành học sau khi ký | Xác minh thất bại |
| P4 | Thu hồi status index 12 | Bị từ chối |
| P5 | Gửi lại cùng nonce | Lần hai bị từ chối |
| P6 | Audience không khớp | Bị từ chối |

## Cấu trúc chính

```text
src/
  credential-service.ts  ký, dẫn xuất và xác minh
  issuer-setup.ts        tạo khóa và document loader
  presentation.ts        nonce, audience và replay guard
  status-store.ts        danh sách thu hồi nhỏ trong RAM
tests/
  credential.test.ts
examples/
  degree-input.json
```

## Giới hạn

- `StatusStore` đang ở trong RAM để PoC dễ chạy. Bản triển khai sau nên đổi sang W3C Bitstring Status List.
- Presentation mới kiểm tra nonce và audience ở tầng ứng dụng, chưa có holder-binding proof.
- Issuer và context dùng URL `example`, chưa được công bố trên Internet.
- Chưa tích hợp OpenID4VCI/OpenID4VP, cơ sở dữ liệu và giao diện người dùng.

## Nguồn kỹ thuật

- [W3C Verifiable Credentials Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/)
- [W3C Data Integrity ECDSA Cryptosuites](https://www.w3.org/TR/vc-di-ecdsa/)
- [Digital Bazaar ECDSA-SD cryptosuite](https://github.com/digitalbazaar/ecdsa-sd-2023-cryptosuite)
- [Digital Bazaar vc.js](https://github.com/digitalbazaar/vc)
