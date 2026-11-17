# Câu hỏi nghiên cứu và hướng dẫn thực nghiệm

| Câu hỏi | Bằng chứng |
|---|---|
| RQ1. Chính sách tiết lộ chọn lọc giảm bao nhiêu thuộc tính nghiệp vụ được gửi trong tuyển dụng, xét học bổng, xác minh chứng chỉ và xác minh bằng lịch sử? | E1. Đối chiếu tập thuộc tính của VC đầy đủ với VC thực sự nằm trong VP, rồi báo riêng các định danh và metadata còn gửi. |
| RQ2. Tiết lộ chọn lọc thay đổi thời gian và kích thước ở từng bước như thế nào, và luồng xác minh thực tế có độ trễ bao nhiêu? | E2. So cặp mật mã trên cùng dữ liệu và ràng buộc giao dịch. E3. Đo HTTP qua cổng, ví lưu ký, verifier, PostgreSQL và Redis. |
| RQ3. Các bất biến nào về toàn vẹn, ràng buộc giao dịch, phân quyền, cô lập và vòng đời đã được kiểm chứng? | E4. Đối chiếu ca kiểm thử được chạy thực tế và kiểm tra vòng đời trên Compose. |

Đóng góp gồm profile và chính sách tiết lộ cho văn bằng, chứng chỉ và hồ sơ cấp lại từ sổ gốc; hiện thực luồng cấp, nhận, trình bày, xác minh và xử lý vòng đời giữa ba dịch vụ; bộ đo và bằng chứng truy vết để định lượng lượng dữ liệu gửi đi, chi phí và phạm vi bảo đảm. Các thuật toán mật mã và giao thức lấy từ các chuẩn liệt kê trong tài liệu thiết kế.

## E1 và E2

Một kịch bản có 25 hồ sơ tổng hợp. Mỗi vòng lấy hồ sơ theo thứ tự và dùng cùng VC chưa ký, holder, issuer, nonce, audience, status entries và document loader cho hai phương án. Các khóa mới sinh theo tiến trình. Chế độ đầy đủ ký VC bằng `ecdsa-rdfc-2019`. Chế độ chọn lọc dùng `ecdsa-sd-2023` để ký base VC và dẫn xuất VC. Cả hai ký VP bằng cùng loại proof holder và kiểm tra chữ ký VC, chữ ký VP, holder DID, challenge và domain. Cả hai dùng callback trạng thái trả hợp lệ nhất quán để cô lập phép đo mật mã. Verifier thực tế có chính sách từ chối thuộc tính dư, do đó baseline đầy đủ chỉ chạy trong E2.

Phép đo E1 đếm trường nghiệp vụ cấp một của `credentialSubject`. Mảng `skills` tính là một trường. DID và đối tượng `legacyProvenance` được ghi riêng. Tỷ lệ giảm là số trường không gửi chia cho số trường nghiệp vụ của VC đầy đủ. Mẫu đo ghi cả metadata còn lộ, kích thước proof và hai mục trạng thái.

E2 đo cấp, dẫn xuất, ký VP, xác minh VC riêng và xác minh VP kèm VC. Đơn vị kích thước là byte UTF-8 của JSON thu gọn. Kết quả ghi từng cặp mẫu, kể cả khởi động và thất bại. Chạy chính gồm 5 tiến trình độc lập, mỗi tiến trình 10 lượt khởi động và 100 lượt đo cho mỗi kịch bản. Thứ tự hai phương án đảo theo vòng, phiên và kịch bản. Bảng báo trung vị, p95 theo nearest rank và kích thước trung vị. JSON tổng hợp giữ độ lệch chuẩn mẫu và thống kê từng phiên. Đây là phép đo lớp thư viện, bao gồm chi phí JSON-LD và ràng buộc proof.

## E3 và E4

E3 xác thực trước, đo nhận bằng lần đầu một lượt trên cơ sở dữ liệu mới, rồi đo từ trước POST tạo yêu cầu đến khi client nhận và đọc kết quả xác minh. Điểm kết thúc bao gồm xem trước, đồng ý tự động, ký tại ví, HTTP direct_post, trạng thái và Redis. Kịch bản dùng một văn bằng và một tài khoản ví với 1, 5, 20, 50 phiên xác minh gửi song song theo nhóm. Mỗi mức có 10 nhóm nối tiếp. Lượt xác minh đầu tiên được lưu riêng, sau đó chạy 10 lượt khởi động. Mẫu tài nguyên docker được lấy sau mỗi mức tải. Kiểm định độ trễ theo môi trường loopback, một ví và `ETAG_REVALIDATE`. Lượt đầu tiên chỉ là một quan sát, còn đo cache có đối chứng thuộc E5.

E4 lưu JSON kết quả Vitest và log hai giai đoạn Compose trên dữ liệu mới. Kiểm tra trước khi tạo lại container xác nhận một VC được trả khi cùng ví nhận đồng thời, hai DID cạnh tranh chỉ có một được nhận, hai danh sách trạng thái độc lập và bằng đình chỉ bị từ chối. Kiểm tra sau đó xác nhận ví và đình chỉ qua lần tạo lại dịch vụ, rồi khôi phục, cấp lại, thu hồi bằng cũ và nhận bằng trên DID mới.

## Tái lập trên Windows

Cần Git, Node, npm, Docker Desktop chạy Linux containers, Python và Matplotlib. Các cổng loopback 18040–18042, 15432 và 6379 cần trống. Dùng một thư mục kết quả mới ngoài bản clone. Script sinh cấu hình riêng cho cụm thử, chỉ đưa metadata phiên bản và cấu hình đo vào manifest, và dọn container cùng volume của cụm đó. Docker image ID và phiên bản dịch vụ được lưu vì tag ảnh Compose có thể được cập nhật.

```powershell
git clone --branch thesis-evaluation-v1 --single-branch <repo-co-tag> digital-credential-eval
cd digital-credential-eval
python -m pip install matplotlib==3.10.9
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/run-evaluation.ps1 -Output ../ket-qua-chinh
```

Thêm `-Mode Pilot` để chạy thử nhanh. Sau khi chạy, `session-*/crypto` và `stack/http` chứa manifest và JSONL. `checks` chứa bằng chứng E4. `summary` chứa CSV, bảng Markdown, JSON tổng hợp và hình PNG. Để dựng lại bảng và hình từ raw data hiện có, dùng lệnh sau.

```powershell
python scripts/summarize-evaluation.py ../ket-qua-chinh ../bang-hinh
```
