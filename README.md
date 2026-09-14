# 🔐 Thủy Vân Số (Digital Watermarking) — Mã Hóa & Giấu Tin

Ứng dụng web nhúng watermark đã mã hóa vào ảnh bằng kỹ thuật **LSB** (Least Significant Bit). Hỗ trợ 3 thuật toán mã hóa mạnh: **AES-GCM**, **ChaCha20**, **RSA** — với tùy chọn **ký số RSA** để xác minh watermark chưa bị thay đổi.

---

## 📋 Mục Đích

- **Nhúng watermark vào ảnh** mà không làm thay đổi ngoại hình
- **Mã hóa watermark** để bảo vệ nội dung nhạy cảm
- **Xác minh tính toàn vẹn** ảnh bằng chữ ký số RSA
- **Trích xuất & giải mã** watermark từ ảnh đã nhúng

---

## ⚙️ Yêu Cầu Hệ Thống

- **Python:** 3.8+
- **Dependencies:** xem file `requirements.txt`

---

## 🚀 Cài Đặt & Chạy

### Bước 1: Cài đặt thư viện

```bash
pip install -r requirements.txt
```

### Bước 2: Chạy ứng dụng

```bash
python app.py
```

### Bước 3: Truy cập

Mở trình duyệt và vào: **http://127.0.0.1:5000**

---

## 📁 Cấu Trúc Thư Mục

```
project_folder/
├── app.py                          # Flask web server
├── backend.py                      # Xử lý LSB watermarking & PSNR
├── thuat_toan_ma_hoa.py           # Các thuật toán mã hóa
├── requirements.txt                # Danh sách thư viện
├── README.md                       # Tài liệu này
└── templates/
    └── index.html                  # Giao diện web (bắt buộc)
```

⚠️ **Lưu ý:** File `index.html` **phải** nằm trong thư mục `templates/`, không để ngoài.

---

## 💡 Hướng Dẫn Sử Dụng

### 1️⃣ Sinh Khóa RSA (Nếu Sử Dụng RSA)

**Khi nào dùng:** Nếu bạn chọn thuật toán **RSA** để mã hóa.

- Nhấp nút **"Sinh khóa RSA"** trên giao diện
- **Copy** cả **khóa công khai** và **khóa riêu tư** lại nơi an toàn
- ⚠️ **Quan trọng:** Khóa **không được lưu trên server**, chỉ hiện ra một lần duy nhất

---

### 2️⃣ Nhúng Watermark Vào Ảnh

**Các bước:**

1. **Chọn ảnh:** Upload file ảnh (PNG, JPG, BMP...)
2. **Nhập watermark:** Gõ nội dung cần giấu (có thể là text, ID, timestamp, v.v.)
3. **Chọn thuật toán mã hóa:**
   - **AES-GCM:** Khóa = mật khẩu (mạnh, nhanh)
   - **ChaCha20:** Khóa = mật khẩu (nhanh hơn AES, an toàn)
   - **RSA:** Khóa = khóa công khai (mã hóa bất đối xứng)

4. **Nhập khóa/mật khẩu:**
   - **AES / ChaCha20:** Gõ mật khẩu tùy ý (có thể dùng nhiều lần)
   - **RSA:** Dán khóa công khai PEM đầy đủ (kể cả dòng `-----BEGIN...-----` và `-----END...-----`)

5. **(Tùy chọn) Ký số:** Nếu muốn chứng minh ảnh chưa bị thay đổi:
   - Dán **khóa riêng tư RSA** vào ô "Khóa riêu tư RSA — tùy chọn"
   - Ảnh sẽ mang theo chữ ký số (chiếm thêm dung lượng)
   - Bỏ trống nếu không cần ký

6. **Tải ảnh:** Nhấp "Nhúng" → Tải ảnh kết quả (PNG) về

---

### 3️⃣ Trích Xuất & Giải Mã Watermark

**Các bước:**

1. **Chọn ảnh đã nhúng** watermark
2. **Chọn thuật toán** (phải giống lúc nhúng)
3. **Nhập khóa/mật khẩu** (phải giống lúc nhúng)
4. **(Tùy chọn) Xác minh chữ ký:**
   - Nếu ảnh được nhúng **có ký số**, dán **khóa công khai** vào ô "Khóa công khai RSA — tùy chọn"
   - Ứng dụng sẽ kiểm tra ảnh có bị chỉnh sửa hay không
   - Bỏ trống nếu không cần xác minh

5. **Nhấp "Trích xuất"** → Xem nội dung watermark gốc

---

## 📊 Kết Quả Trích Xuất

| Trường hợp | Kết quả |
|-----------|---------|
| **Sai thuật toán hoặc sai khóa** | Lỗi rõ ràng (không hiển thị nội dung sai) |
| **Chữ ký hợp lệ** ✓ | "Chữ ký hợp lệ — ảnh chưa bị thay đổi" |
| **Chữ ký không hợp lệ** ✗ | "Chữ ký không hợp lệ — ảnh có thể bị thay đổi" |
| **Có chữ ký nhưng không dán khóa công khai** | Vẫn hiển thị watermark, bỏ qua xác minh |
| **Không có chữ ký nhúng** | Không xác minh, hiển thị watermark bình thường |

---

## 🔍 Đánh Giá Chất Lượng Ảnh (PSNR)

Ứng dụng tính **PSNR** (Peak Signal-to-Noise Ratio) để đánh giá mức độ "vô hình" của watermark:

| PSNR (dB) | Đánh giá |
|-----------|---------|
| **≥ 40** | 🟢 Rất tốt — watermark gần như không thể nhận biết bằng mắt thường |
| **30 - 40** | 🟡 Tốt — watermark khó nhận biết |
| **20 - 30** | 🟠 Trung bình — có thể nhận thấy sai khác nhẹ khi quan sát kỹ |
| **< 20** | 🔴 Kém — sai khác dễ nhận biết bằng mắt thường |

---

## ⚠️ Lưu Ý Kỹ Thuật

### 🔑 Quản Lý Khóa RSA

- **Khóa có nhiều dòng:** Bắt buộc dán vào ô **textarea** (giao diện tự chuyển khi chọn RSA), không dán vào ô một dòng
- **Mất ký tự xuống dòng** → Khóa bị hỏng → Lỗi mã hóa/giải mã
- **Bảo quản khóa riêu tư:** Giữ ở nơi an toàn, không chia sẻ công khai

### 📏 Giới Hạn RSA

- **RSA chỉ mã hóa được ~190 byte** (với khóa 2048-bit)
- Nếu watermark quá dài → Mã hóa lỗi
- **Giải pháp:** Dùng **AES** hoặc **ChaCha20** để mã hóa watermark dài

### 🖼️ Định Dạng Ảnh

- **Ảnh đầu ra:** Luôn là **PNG** (không mất dữ liệu)
- **Tại sao:** Định dạng JPG nén ảnh → phá hỏng các bit LSB đã nhúng
- **Khuyến cáo:** Không sử dụng lại ảnh JPG đã nhúng watermark; đầu ra luôn PNG

### 💾 Bảo Mật Server

- **Xử lý hoàn toàn trong RAM** — không lưu file nào trên server
- **Không giữ khóa** — người dùng tự quản lý
- **Mỗi phiên độc lập** — khi đóng trình duyệt, dữ liệu bị xóa

---

## 📚 Thuật Toán Mã Hóa

### 1. AES-GCM (Advanced Encryption Standard)
- **Loại:** Mã hóa đối xứng
- **Độ an toàn:** Rất cao (256-bit)
- **Tốc độ:** Nhanh
- **Khóa:** Mật khẩu (bất kỳ độ dài)
- **Ưu điểm:** Chuẩn công nghiệp, có xác thực dữ liệu

### 2. ChaCha20
- **Loại:** Mã hóa dòng
- **Độ an toàn:** Rất cao
- **Tốc độ:** Nhanh hơn AES
- **Khóa:** Mật khẩu (bất kỳ độ dài)
- **Ưu điểm:** Tối ưu cho thiết bị di động và embedded

### 3. RSA (Rivest-Shamir-Adleman)
- **Loại:** Mã hóa bất đối xứng
- **Độ an toàn:** Rất cao (2048-bit)
- **Tốc độ:** Chậm hơn AES
- **Khóa:** Công khai / Riêu tư
- **Ưu điểm:** Cho phép ký số xác minh nguồn gốc

---

## 🛠️ Giải Quyết Sự Cố

| Lỗi | Nguyên Nhân | Giải Pháp |
|-----|-----------|----------|
| **"Ảnh không đủ dung lượng"** | Ảnh quá nhỏ hoặc watermark quá dài | Dùng ảnh lớn hơn hoặc watermark ngắn hơn |
| **"Sai mật khẩu/khóa"** | Mật khẩu/khóa không khớp | Kiểm tra lại, đảm bảo chính xác |
| **"Khóa RSA hỏng"** | Copy khóa mất ký tự xuống dòng | Dán khóa vào textarea, bao gồm `-----BEGIN/END-----` |
| **"RSA không mã hóa được"** | Watermark > 190 byte | Dùng AES hoặc ChaCha20 thay thế |
| **"Chữ ký không hợp lệ"** | Sai khóa công khai hoặc ảnh bị chỉnh sửa | Kiểm tra lại khóa, hoặc ảnh bị thay đổi |
| **Không tìm thấy watermark** | Ảnh không được nhúng, hoặc ảnh được nén lại (JPG) | Kiểm tra lại ảnh, dùng ảnh PNG gốc |

---

## 📝 Ví Dụ Workflow

### Ví dụ 1: Dùng AES-GCM (Đơn Giản)

```
1. Nhúng:
   - Chọn ảnh: cat.jpg
   - Watermark: "Copyright © 2025"
   - Mã hóa: AES-GCM
   - Mật khẩu: "MySecretPass123"
   → Tải: cat_watermarked.png

2. Trích xuất:
   - Chọn ảnh: cat_watermarked.png
   - Mã hóa: AES-GCM
   - Mật khẩu: "MySecretPass123"
   → Kết quả: "Copyright © 2025" ✓
```

### Ví dụ 2: Dùng RSA + Ký Số (Nâng Cao)

```
1. Sinh khóa:
   - Nhấp "Sinh khóa RSA"
   - Copy khóa công khai & khóa riêu tư

2. Nhúng:
   - Chọn ảnh: document.png
   - Watermark: "OFFICIAL-2025"
   - Mã hóa: RSA
   - Khóa công khai: [dán khóa]
   - Khóa riêu tư (ký số): [dán khóa]
   → Tải: document_signed.png

3. Trích xuất & Xác minh:
   - Chọn ảnh: document_signed.png
   - Mã hóa: RSA
   - Khóa riêu tư: [dán khóa]
   - Khóa công khai (xác minh): [dán khóa]
   → Kết quả: "OFFICIAL-2025" ✓
   → Chữ ký: "Hợp lệ — ảnh chưa bị thay đổi" ✓
```