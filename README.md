# Thủy vân số — Mã hóa & Giấu tin

Web app nhúng watermark đã mã hóa vào ảnh bằng kỹ thuật LSB. Hỗ trợ 3 thuật toán: AES, ChaCha20, RSA.

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

1. **Sinh khóa RSA** (chỉ cần nếu bạn chọn thuật toán RSA) — bấm nút, copy khóa công khai và khóa riêng tư lại, lưu ý là khóa **không được lưu ở server**.
2. **Nhúng watermark** — chọn ảnh, nhập nội dung cần giấu, chọn thuật toán + khóa, tải ảnh kết quả về.
3. **Trích xuất watermark** — chọn ảnh đã nhúng, nhập đúng thuật toán + khóa đã dùng lúc nhúng, xem lại nội dung gốc.

## Lưu ý

- AES / ChaCha20: khóa là **mật khẩu** bất kỳ do bạn đặt.
- RSA: nhúng dùng **khóa công khai**, trích xuất dùng **khóa riêng tư**.
- Toàn bộ xử lý ảnh diễn ra trong RAM, không lưu file nào lên server.
