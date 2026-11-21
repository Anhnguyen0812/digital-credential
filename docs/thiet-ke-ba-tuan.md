# Thiết kế và truy vết của ba tuần cải tiến

## Quyết định kiến trúc

Chọn ví lưu ký để hoàn thành luồng cấp, nhận, trình bày và cấp lại bằng giao diện hiện có. Dịch vụ ví xác định chủ sở hữu từ phiên đăng nhập rồi lưu khóa, văn bằng và lịch sử trong bản ghi mã hóa của sinh viên đó. Verifier nhận bản trình bày dẫn xuất. Quyền vận hành ví và quản lý WALLET_STORAGE_KEY nằm trong ranh giới tin cậy. Bản sao lưu mã hóa có chủ sở hữu và đòi hỏi nhập lại mật khẩu. Việc đổi khóa tạo DID mới. Cấp lại cần hồ sơ được phê duyệt và thu hồi văn bằng trước đó.

~~~mermaid
flowchart LR
  S[Sinh viên] --> W[Dịch vụ ví theo tài khoản]
  H[Nhân sự tuyển dụng] --> V[Verifier theo tổ chức]
  C[Cán bộ nhà trường] --> I[Issuer và quy trình phê duyệt]
  I -->|Cấp bằng gắn DID| W
  W -->|Bản trình bày chọn lọc| V
  V -->|Tra cứu hai danh sách trạng thái| I
  W --> P[(Kho ví mã hóa)]
  I --> D[(Hồ sơ và chỉ số PostgreSQL)]
  W --> R[(Phiên Redis)]
  V --> R
  I --> R
~~~

Bên nhà trường là nguồn dữ liệu gốc và giữ khóa ký. Dịch vụ ví giữ khóa của từng holder. Một khóa cấu hình bảo vệ mật liệu ví khi lưu. KMS/HSM, xoay vòng khóa ký tự động, cơ chế khóa chống xuất trên thiết bị và xác thực VNeID thật thuộc phạm vi nghiên cứu tiếp theo. Bản ghi PostgreSQL từ luồng portal được giữ lại. Ví dùng chung trước đây chỉ tồn tại trong RAM. Chủ văn bằng cũ dùng quy trình cấp lại để gắn với ví mới. Hệ thống vẫn kiểm tra credential cũ chỉ chứa một mục revocation.

## Yêu cầu và bằng chứng

| Công việc | Yêu cầu hoặc đe dọa | Mã nguồn | Kiểm tra | Câu hỏi nghiên cứu |
|---|---|---|---|---|
| B01 | Phát hành và thu hồi ngoài quyền | [Issuer](../src/services/issuer-app.ts), [cổng nhà trường](../src/portal/issuer-portal.ts) | [Portal](../tests/portals.test.ts) | RQ3 |
| B02 | Hai sinh viên dùng chung DID hoặc lộ khóa qua backup | [Kho ví theo tài khoản](../src/portal/wallet-portal.ts) | [Portal](../tests/portals.test.ts), [Compose](../scripts/check-compose.ts) | RQ1, RQ3 |
| B03 | Lộ lịch sử, receipt hoặc sự kiện sang doanh nghiệp khác | [Cổng tuyển dụng](../src/portal/verifier-portal.ts), [Verifier](../src/services/verifier-app.ts) | [Portal](../tests/portals.test.ts) | RQ3 |
| B04 | Mất đình chỉ sau khởi động | [Hai danh sách trạng thái](../src/status/status-store.ts), [khôi phục từ hồ sơ](../src/portal/issuer-portal.ts) | [Compose](../scripts/check-compose.ts) | RQ3 |
| B05 | Bản trình bày không đạt làm mất nonce | [Verifier](../src/services/verifier-app.ts), [Redis NX](../src/infra/redis-replay-guard.ts) | [Dịch vụ](../tests/services.test.ts) | RQ3 |
| B06 | Nhận trùng, cấp lại lô bỏ sót thu hồi | [Giao dịch và chỉ số duy nhất](../src/infra/doc-store.ts), [cổng nhà trường](../src/portal/issuer-portal.ts) | [Compose](../scripts/check-compose.ts) | RQ3 |
| B07 | Lệch quyền hoặc phiên giữa hai tiến trình | [Phiên Redis với giới hạn tuyệt đối](../src/auth/session.ts), [kiểm tra tài khoản](../src/portal/issuer-portal.ts) | [Phiên tuần 9](../tests/week9.test.ts) | RQ3 |
| B08 | Lộ khóa lưu trữ hoặc thay khóa khi di trú | [Bọc khóa](../src/crypto/key-vault.ts), [di trú](../src/services/issuer-app.ts), [cấu hình](../src/services/runtime-config.ts) | [Kho khóa tuần 9](../tests/week9.test.ts), [Compose](../scripts/check-compose.ts) | RQ3 |
| B09 | Chữ ký đúng nhưng dữ liệu sai yêu cầu | [Chính sách trình bày](../src/profiles/presentation-policy.ts), [Verifier](../src/services/verifier-app.ts) | [Dịch vụ](../tests/services.test.ts) | RQ1, RQ3 |
| B10 | Sai transport hoặc ràng buộc trong trao đổi | [Bộ đọc direct_post](../src/services/http-util.ts), [proof ES256](../src/crypto/credential-proof.ts) | [Dịch vụ](../tests/services.test.ts), [Compose](../scripts/check-compose.ts) | RQ3 |
| B11 | Kết luận thiếu truy vết | Sơ đồ và bảng yêu cầu trong tài liệu này | Đối chiếu với [đề cương thực nghiệm](thuc-nghiem.md) | RQ1–RQ3 |

RQ1 đo mức tiết lộ, RQ2 đo thời gian và kích thước, RQ3 kiểm tra các bất biến an toàn. Các ca kiểm thử chức năng hỗ trợ RQ3. [Đề cương thực nghiệm](thuc-nghiem.md) định nghĩa cách đo RQ1 và RQ2.

## Cơ chế tiết lộ chọn lọc

ECDSA-SD chuẩn hóa JSON-LD thành tập phát biểu RDF và chia chúng thành nhóm bắt buộc và nhóm có thể tiết lộ. Khóa ký dài hạn của issuer tạo chữ ký cơ sở ràng buộc cấu hình proof, nhóm bắt buộc và khóa công khai dành riêng cho proof đó. Khóa riêng dành cho proof ký các phát biểu thuộc nhóm có thể tiết lộ. Khi dẫn xuất, ví giữ bằng chứng cho các phát biểu đã chọn và gửi chúng cùng nhóm bắt buộc. Chữ ký do holder tạo trên VP phục vụ ràng buộc với phiên xác minh.

SD-JWT dùng JWT do issuer ký để xác thực các digest của Disclosure có salt. Holder gửi các Disclosure cần dùng, kể cả đối với cấu trúc JSON lồng nhau. Khi giao dịch yêu cầu key binding, SD-JWT+KB thêm JWT do holder ký chứa hash của SD-JWT trình bày, nonce và audience. ECDSA-SD trong hệ thống dùng phát biểu RDF và ký VP riêng để ràng buộc giao dịch. Phép đo so sánh triển khai ECDSA-SD với `ecdsa-rdfc-2019`. SD-JWT được khảo sát ở mức thiết kế. [W3C §3.6](https://www.w3.org/TR/2025/REC-vc-di-ecdsa-20250515/#ecdsa-sd-2023), [RFC 9901 §4](https://www.rfc-editor.org/rfc/rfc9901.html#section-4), [RFC 9901 §6](https://www.rfc-editor.org/rfc/rfc9901.html#section-6)

## Đối chiếu giao thức

| Thành phần | Đã triển khai | Phạm vi còn lại |
|---|---|---|
| OpenID4VP 1.0 §6 và §8.2 | Một credential DCQL, ldp_vc, POST form UTF-8, state, nonce, client ID và holder proof | Luồng ví–verifier đã được kiểm chứng nội bộ. Request URI trả JSON. Kiểm thử liên thông ví ngoài còn mở |
| OpenID4VCI 1.0 Phụ lục F.1 | Proof JWT ES256 có kid gắn DID, nonce, aud là URL issuer và iat | Endpoint cấp phát và đăng nhập nội bộ. Metadata chuẩn, OAuth grant và credential offer ngoài phạm vi hiện tại |
| Bitstring Status List 1.0 | Hai danh sách có chữ ký và mục đích riêng, ETag | TTL cho phép dùng bản cũ trong khoảng đã cấu hình. Hai lần lấy danh sách là hai thao tác mạng |
| Định danh | Đăng nhập trường và VNeID đều là mô phỏng, với JWT ES256 và JWKS nội bộ | Tích hợp thực tế và các bước OIDC chuẩn chưa được đánh giá |

~~~mermaid
sequenceDiagram
  actor SV as Người học
  participant W as Dịch vụ ví lưu ký
  participant I as Issuer và định danh mô phỏng
  actor HR as Nhân sự tuyển dụng
  participant V as Verifier
  SV->>W: Đăng nhập và chọn nhận văn bằng
  W->>I: Lấy nonce, gửi proof JWT ES256
  I-->>W: Base VC gắn DID của ví
  Note over W: Khóa holder và Base VC lưu mã hóa theo tài khoản
  HR->>V: Tạo phiên và chọn thuộc tính cần
  V-->>HR: Yêu cầu DCQL nội bộ
  SV->>W: Mở yêu cầu và xem trước dữ liệu
  W->>V: Đọc lại yêu cầu theo phiên
  SV->>W: Xác nhận chia sẻ
  W->>V: direct_post với Derived VC trong VP đã ký
  V->>I: Kiểm tra danh sách thu hồi và đình chỉ
  V-->>W: Kết quả xác minh
~~~

Khóa giao dịch PostgreSQL hiện theo tên bảng. Cách này giữ bất biến giữa các tiến trình nhưng có thể giảm khả năng xử lý đồng thời khi số người dùng tăng. Audit log được lưu riêng, chưa được bảo đảm nguyên tử cùng mọi cập nhật hồ sơ. Phiên xác minh và challenge phát hành nằm trong tiến trình tạo chúng. Khi tiến trình khởi động lại, tạo yêu cầu mới để tiếp tục.

## Nguồn chuẩn

- [W3C Verifiable Credentials Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/)
- [W3C Data Integrity ECDSA Cryptosuites 1.0](https://www.w3.org/TR/vc-di-ecdsa/)
- [W3C Bitstring Status List 1.0](https://www.w3.org/TR/vc-bitstring-status-list/)
- [OpenID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- [OpenID4VCI 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
- [RFC 9901 §6 về SD-JWT lồng nhau](https://www.rfc-editor.org/rfc/rfc9901.html#section-6)
