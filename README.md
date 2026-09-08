# PoC chứng chỉ số – Tuần 04

Bài thực hành minh họa quy trình cấp và xác minh bằng tốt nghiệp số: nhà trường ký chứng chỉ, sinh viên lựa chọn thông tin chia sẻ và đơn vị tuyển dụng xác minh tính hợp lệ.

## Công nghệ và cách chạy

Dự án sử dụng Node.js 20 trở lên, TypeScript, pnpm, W3C Verifiable Credentials 2.0, ECDSA-SD-2023 của Digital Bazaar và Vitest.

```bash
pnpm install
pnpm check
pnpm demo
pnpm benchmark
```

`pnpm check` kiểm tra kiểu dữ liệu và chạy bộ kiểm thử. `pnpm demo` tạo chứng chỉ đã ký, bản chia sẻ và bản trình bày trong `.demo-output/`. `pnpm benchmark` đo thời gian cấp, dẫn xuất, xác minh và kích thước dữ liệu sau 5 vòng khởi động, với 30 vòng đo; kết quả được lưu tại `.demo-output/benchmark.json`.

## Chức năng và kiểm thử

- Cấp và xác minh chứng chỉ bằng khóa ECDSA P-256.
- Chia sẻ có chọn lọc các trường `id`, `studentName`, `major` và `graduated` của sinh viên; ẩn các thông tin còn lại.
- Phát hiện nội dung bị sửa đổi và từ chối chứng chỉ đã thu hồi.
- Kiểm tra mã dùng một lần (`nonce`), bên nhận (`audience`) và ngăn sử dụng lại nonce.

Bộ kiểm thử gồm 6 trường hợp: xác minh chứng chỉ gốc, chia sẻ có chọn lọc, sửa đổi nội dung, thu hồi chứng chỉ, sử dụng lại nonce và sai bên nhận.

Mã nguồn nằm trong `src/`, bộ kiểm thử trong `tests/` và dữ liệu đầu vào mẫu tại `examples/degree-input.json`.

## Giới hạn

- Khóa được tạo mới trong bộ nhớ mỗi lần chạy, không lưu khóa riêng. Danh sách thu hồi cũng chỉ lưu trong bộ nhớ, chưa triển khai W3C Bitstring Status List.
- Bản trình bày kiểm tra nonce và audience ở tầng ứng dụng, chưa có bằng chứng mật mã ràng buộc người nắm giữ chứng chỉ.
- Định danh đơn vị cấp và ngữ cảnh dữ liệu sử dụng URL minh họa. Dự án chưa tích hợp OpenID4VCI/OpenID4VP, cơ sở dữ liệu hoặc giao diện người dùng.

## Tài liệu tham khảo

- [W3C Verifiable Credentials Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/)
- [W3C Data Integrity ECDSA Cryptosuites](https://www.w3.org/TR/vc-di-ecdsa/)
- [Digital Bazaar ECDSA-SD](https://github.com/digitalbazaar/ecdsa-sd-2023-cryptosuite)
