# Thủy vân số — Mã hóa & Giấu tin

Web app nhúng watermark đã mã hóa vào ảnh bằng kỹ thuật LSB (Least Significant Bit). Hỗ trợ 3 thuật toán mã hóa: **AES-GCM**, **ChaCha20**, **RSA** — RSA còn hỗ trợ **ký số** để xác minh watermark chưa bị thay đổi.

## Cài đặt

```bash
pip install -r requirements.txt
```

## Chạy

```bash
python app.py
```

Mở trình duyệt vào: **http://127.0.0.1:5000**

## Cấu trúc thư mục (bắt buộc phải đúng)

```
baitaplon1/
├── app.py
├── backend.py
├── thuat_toan_ma_hoa.py
├── requirements.txt
└── templates/
    └── index.html
```

⚠️ File `index.html` phải nằm trong thư mục `templates/`, không để ngoài.

## Cách dùng

### 1. Sinh khóa RSA
Chỉ cần nếu bạn chọn thuật toán RSA. Bấm nút **Sinh khóa**, copy khóa công khai và khóa riêng tư lại — khóa **không được lưu ở server**, chỉ hiện ra một lần.

### 2. Nhúng watermark
Chọn ảnh, nhập nội dung cần giấu, chọn thuật toán + khóa, tải ảnh kết quả (PNG) về.

- **AES / ChaCha20**: khóa là **mật khẩu** bất kỳ do bạn đặt.
- **RSA**: khóa dùng để nhúng là **khóa công khai** (dán nguyên khối PEM, kể cả dòng `-----BEGIN...-----` / `-----END...-----`).
- **Ký số (tùy chọn, chỉ RSA)**: dán thêm **khóa riêng tư** vào ô "Khóa riêng tư RSA — tùy chọn, để ký watermark" nếu muốn ảnh mang theo chữ ký số. Bỏ trống nếu không cần.
  - Có ký số sẽ chiếm thêm dung lượng nhúng đáng kể so với không ký — nếu ảnh quá nhỏ, chương trình báo lỗi "không đủ dung lượng" thay vì nhúng thiếu.

### 3. Trích xuất watermark
Chọn ảnh đã nhúng, nhập đúng thuật toán + khóa đã dùng lúc nhúng, xem lại nội dung gốc.

- **AES / ChaCha20**: nhập lại đúng mật khẩu.
- **RSA**: khóa dùng để trích xuất là **khóa riêng tư** (dán nguyên khối PEM).
- **Xác minh chữ ký (tùy chọn, chỉ RSA)**: nếu ảnh được nhúng kèm chữ ký, dán **khóa công khai** vào ô "Khóa công khai RSA — tùy chọn, để xác minh chữ ký" để kiểm tra ảnh có bị thay đổi hay không:
  - ✓ **Chữ ký hợp lệ** — ảnh chưa bị thay đổi.
  - ℹ️ **Có chữ ký nhưng chưa xác minh** — nếu bạn không dán khóa công khai, chương trình vẫn giải mã và hiện watermark bình thường, chỉ bỏ qua bước xác minh.
  - Nếu dán **sai** khóa công khai (hoặc dữ liệu bị chỉnh sửa), chương trình báo lỗi rõ ràng thay vì hiện watermark sai.

Nếu chọn sai thuật toán hoặc sai khóa/mật khẩu, chương trình trả về lỗi rõ ràng thay vì nội dung không đọc được.

## Lưu ý kỹ thuật

- Toàn bộ xử lý ảnh diễn ra trong RAM, không lưu file nào lên server.
- Khóa RSA (PEM) có nhiều dòng — bắt buộc dán vào ô dạng textarea (giao diện tự chuyển sang textarea khi chọn RSA), **không** dán vào ô một dòng vì sẽ làm mất ký tự xuống dòng và hỏng khóa.
- RSA-OAEP chỉ mã hóa được tối đa khoảng 190 byte văn bản gốc (với khóa 2048-bit) — watermark quá dài sẽ mã hóa lỗi; nếu cần watermark dài, dùng AES hoặc ChaCha20.
- Ảnh đầu ra luôn là PNG (định dạng không mất dữ liệu) để giữ nguyên các bit LSB đã nhúng — không dùng lại ảnh JPG đã nhúng vì nén JPEG sẽ phá hỏng watermark.
