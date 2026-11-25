# Văn bằng học tập số

Hệ thống thử nghiệm gồm cổng nhà trường, ví lưu ký theo từng sinh viên và cổng tuyển dụng. Nhà trường cấp văn bằng JSON-LD bằng ECDSA-SD. Ví xem trước dữ liệu, dẫn xuất bản trình bày và ký gắn với phiên xác minh. Luồng đăng nhập dùng tài khoản mô phỏng.

## Chạy cục bộ với Docker Compose

Yêu cầu Docker có Compose và Node.js 24 cho kiểm thử. Sao chép .env.example thành .env. Điền POSTGRES_PASSWORD bằng chuỗi an toàn cho URL. Dùng các giá trị ngẫu nhiên độc lập có từ 32 ký tự cho MASTER_KMS_KEY, SESSION_SECRET, RECEIPT_SECRET và WALLET_STORAGE_KEY. Điền DEMO_PASSWORD từ 12 ký tự. Dùng lại cùng cấu hình khi tạo lại container và lưu cấu hình ở nơi an toàn.

~~~powershell
Copy-Item .env.example .env
npm ci
docker compose up --build -d --wait
~~~

| Cổng | Địa chỉ | Tài khoản mẫu |
|---|---|---|
| Nhà trường | http://localhost:4001/issuer.html | chuyenvien, truongphong, admin |
| Ví sinh viên | http://localhost:3000/wallet.html | 23020009@vnu.edu.vn, 23020114@vnu.edu.vn |
| Tuyển dụng | http://localhost:4002/verifier.html | hr.fpt, hr.viettel |

Mọi tài khoản mẫu dùng DEMO_PASSWORD đã đặt khi cơ sở dữ liệu được tạo. PostgreSQL lưu dữ liệu trên named volume. Các cổng mặc định chỉ bind ở loopback. Để thử luồng, đăng nhập ví và nhận hồ sơ đã duyệt. Sau đó đăng nhập tuyển dụng, tạo yêu cầu, sao chép request URI vào ví, xem trước và gửi.

## Kiểm thử

~~~powershell
docker compose up -d redis-guard
npm run check
~~~

Lệnh trên cần .env nếu dùng Compose cho Redis. Suite chuẩn dùng Redis tại 127.0.0.1:6379 và kho bộ nhớ cho ứng dụng. Test PostgreSQL/Redis thật dùng một project Compose riêng và dữ liệu mẫu. Đặt DEMO_PASSWORD trong môi trường shell trùng với cấu hình cụm. Đặt ISSUER_PUBLIC_URL, VERIFIER_PUBLIC_URL, COMPOSE_WALLET_URL nếu dùng cổng riêng.

~~~powershell
npm run check:compose -- before-recreate
docker compose up -d --force-recreate --wait
npm run check:compose -- after-recreate
~~~

Chạy hai giai đoạn trên cụm thử mới. Giai đoạn đầu đình chỉ một văn bằng đã cấp. Giai đoạn sau kiểm tra trạng thái còn hiệu lực qua việc tạo lại container, rồi khôi phục và cấp lại. Demo lịch sử chỉ chạy cục bộ với các entrypoint và cấu hình bộ nhớ riêng. Dùng npm run start:prototype để xem bản prototype tích hợp tuần 7 trên loopback.
