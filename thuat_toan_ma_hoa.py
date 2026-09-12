"""
thuat_toan_ma_hoa.py
Các hàm mã hóa / giải mã đối xứng dùng cho bài thực hành Thủy vân số (Watermarking).
Sử dụng thư viện PyCryptodome.

Cài đặt thư viện (nếu chưa có):
    pip install pycryptodome

Hai thuật toán được chọn: AES (chế độ GCM) và ChaCha20.
- AES-GCM: vừa mã hóa vừa xác thực (kèm tag), đúng khuyến nghị trong Phần A báo cáo.
- ChaCha20: thuật toán mã dòng, tốc độ tốt, dùng để so sánh với AES.

Đầu ra của các hàm mã hóa là một CHUỖI (string) dạng Base64, có thể truyền thẳng
vào hàm nhung_thong_diep(anh_goc, anh_dich, encrypt) trong backend.py.
"""

import base64
from Crypto.Cipher import AES, ChaCha20, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes


# ============================================================
# HÀM DÙNG CHUNG: Chuyển khóa người dùng nhập (dạng text) 
# thành khóa nhị phân 32 byte (256-bit) bằng PBKDF2
# ============================================================
def tao_khoa_tu_mat_khau(mat_khau, salt, do_dai_khoa=32, vong_lap=100_000):
    """
    Sinh khóa nhị phân từ mật khẩu do người dùng nhập.
    - mat_khau: chuỗi khóa người dùng nhập (str)
    - salt: bytes ngẫu nhiên dùng để tăng độ an toàn (nên lưu kèm bản mã)
    - do_dai_khoa: độ dài khóa mong muốn (byte), mặc định 32 byte = 256 bit
    """
    khoa = PBKDF2(
        mat_khau.encode('utf-8'),
        salt,
        dkLen=do_dai_khoa,
        count=vong_lap,
        hmac_hash_module=SHA256
    )
    return khoa


# ============================================================
# 1. AES - GCM (mã hóa đối xứng, có xác thực)
# ============================================================
def ma_hoa_aes(van_ban_goc, mat_khau):
    """
    Mã hóa văn bản bằng AES-GCM.
    Trả về 1 chuỗi Base64 gồm: salt (16 byte) + nonce (16 byte) + tag (16 byte) + bản mã
    -> Có thể truyền thẳng chuỗi này vào nhung_thong_diep().
    """
    salt = get_random_bytes(16)
    khoa = tao_khoa_tu_mat_khau(mat_khau, salt)

    cipher = AES.new(khoa, AES.MODE_GCM)
    ban_ma, tag = cipher.encrypt_and_digest(van_ban_goc.encode('utf-8'))

    # Gộp tất cả thành phần cần thiết để giải mã lại về sau
    du_lieu_gop = salt + cipher.nonce + tag + ban_ma
    return base64.b64encode(du_lieu_gop).decode('utf-8')


def giai_ma_aes(chuoi_base64, mat_khau):
    """
    Giải mã chuỗi Base64 được tạo bởi ma_hoa_aes().
    Trả về văn bản gốc (str), hoặc None nếu sai khóa / dữ liệu bị thay đổi.
    """
    try:
        du_lieu_gop = base64.b64decode(chuoi_base64)

        salt = du_lieu_gop[:16]
        nonce = du_lieu_gop[16:32]
        tag = du_lieu_gop[32:48]
        ban_ma = du_lieu_gop[48:]

        khoa = tao_khoa_tu_mat_khau(mat_khau, salt)
        cipher = AES.new(khoa, AES.MODE_GCM, nonce=nonce)
        van_ban_goc = cipher.decrypt_and_verify(ban_ma, tag)

        return van_ban_goc.decode('utf-8')
    except (ValueError, KeyError):
        # Sai khóa hoặc dữ liệu bị hỏng/sửa đổi -> AES-GCM sẽ phát hiện được
        print("=> Lỗi: Sai khóa hoặc dữ liệu đã bị thay đổi (AES).")
        return None


# ============================================================
# 2. ChaCha20 (mã hóa đối xứng, mã dòng)
# ============================================================
def ma_hoa_chacha20(van_ban_goc, mat_khau):
    """
    Mã hóa văn bản bằng ChaCha20.
    Trả về 1 chuỗi Base64 gồm: salt (16 byte) + nonce (8 byte) + bản mã
    -> Có thể truyền thẳng chuỗi này vào nhung_thong_diep().
    """
    salt = get_random_bytes(16)
    khoa = tao_khoa_tu_mat_khau(mat_khau, salt)

    cipher = ChaCha20.new(key=khoa)
    ban_ma = cipher.encrypt(van_ban_goc.encode('utf-8'))

    du_lieu_gop = salt + cipher.nonce + ban_ma
    return base64.b64encode(du_lieu_gop).decode('utf-8')


def giai_ma_chacha20(chuoi_base64, mat_khau):
    """
    Giải mã chuỗi Base64 được tạo bởi ma_hoa_chacha20().
    Trả về văn bản gốc (str), hoặc None nếu có lỗi.
    """
    try:
        du_lieu_gop = base64.b64decode(chuoi_base64)

        salt = du_lieu_gop[:16]
        nonce = du_lieu_gop[16:24]   # ChaCha20 nonce mặc định 8 byte
        ban_ma = du_lieu_gop[24:]

        khoa = tao_khoa_tu_mat_khau(mat_khau, salt)
        cipher = ChaCha20.new(key=khoa, nonce=nonce)
        van_ban_goc = cipher.decrypt(ban_ma)

        return van_ban_goc.decode('utf-8')
    except (ValueError, UnicodeDecodeError):
        print("=> Lỗi: Sai khóa hoặc dữ liệu đã bị thay đổi (ChaCha20).")
        return None


# ============================================================
# 3. RSA (mã hóa BẤT ĐỐI XỨNG - dùng cặp khóa công khai/riêng tư)
# ============================================================
def tao_cap_khoa_rsa(do_dai_bit=2048):
    """
    Sinh cặp khóa RSA (khóa công khai + khóa riêng tư).
    - do_dai_bit: độ dài khóa, nên dùng 2048 trở lên (mặc định 2048).
    Trả về tuple (khoa_cong_khai_pem, khoa_rieng_tu_pem) dạng chuỗi (str),
    để dễ lưu ra file .pem hoặc hiển thị trên giao diện web.
    """
    khoa = RSA.generate(do_dai_bit)
    khoa_rieng_tu_pem = khoa.export_key().decode('utf-8')
    khoa_cong_khai_pem = khoa.publickey().export_key().decode('utf-8')
    return khoa_cong_khai_pem, khoa_rieng_tu_pem


def ma_hoa_rsa(van_ban_goc, khoa_cong_khai_pem):
    """
    Mã hóa văn bản bằng RSA (dùng khóa CÔNG KHAI), đệm PKCS1_OAEP.
    Lưu ý: RSA chỉ mã hóa được dữ liệu ngắn (giới hạn theo độ dài khóa,
    ví dụ khóa 2048-bit mã hóa tối đa ~190 byte dữ liệu mỗi lần).
    -> Vì vậy RSA thường dùng để mã hóa 1 khóa đối xứng (AES/ChaCha20)
       chứ không dùng để mã hóa trực tiếp watermark dài.
    Trả về chuỗi Base64.
    """
    khoa_cong_khai = RSA.import_key(khoa_cong_khai_pem)
    cipher = PKCS1_OAEP.new(khoa_cong_khai)
    ban_ma = cipher.encrypt(van_ban_goc.encode('utf-8'))
    return base64.b64encode(ban_ma).decode('utf-8')


def giai_ma_rsa(chuoi_base64, khoa_rieng_tu_pem):
    """
    Giải mã chuỗi Base64 được tạo bởi ma_hoa_rsa(), dùng khóa RIÊNG TƯ.
    Trả về văn bản gốc (str), hoặc None nếu sai khóa / dữ liệu bị hỏng.
    """
    try:
        khoa_rieng_tu = RSA.import_key(khoa_rieng_tu_pem)
        cipher = PKCS1_OAEP.new(khoa_rieng_tu)
        ban_ma = base64.b64decode(chuoi_base64)
        van_ban_goc = cipher.decrypt(ban_ma)
        return van_ban_goc.decode('utf-8')
    except (ValueError, TypeError):
        print("=> Lỗi: Sai khóa hoặc dữ liệu đã bị thay đổi (RSA).")
        return None


def rsa_ma_hoa_khoa_doi_xung(khoa_doi_xung_bytes, khoa_cong_khai_pem):
    """
    Mô hình lai (hybrid) thường dùng trong thực tế:
    Dùng RSA để mã hóa MỘT KHÓA ĐỐI XỨNG (vd khóa AES 32 byte),
    sau đó dùng khóa đối xứng đó để mã hóa watermark (nhanh hơn nhiều so với
    mã hóa trực tiếp văn bản dài bằng RSA).
    Trả về chuỗi Base64 của khóa đối xứng đã được mã hóa bằng RSA.
    """
    khoa_cong_khai = RSA.import_key(khoa_cong_khai_pem)
    cipher = PKCS1_OAEP.new(khoa_cong_khai)
    khoa_da_ma_hoa = cipher.encrypt(khoa_doi_xung_bytes)
    return base64.b64encode(khoa_da_ma_hoa).decode('utf-8')


def rsa_giai_ma_khoa_doi_xung(chuoi_base64, khoa_rieng_tu_pem):
    """Giải mã lại khóa đối xứng đã được mã hóa bằng RSA (xem hàm trên)."""
    khoa_rieng_tu = RSA.import_key(khoa_rieng_tu_pem)
    cipher = PKCS1_OAEP.new(khoa_rieng_tu)
    khoa_da_ma_hoa = base64.b64decode(chuoi_base64)
    return cipher.decrypt(khoa_da_ma_hoa)


# ============================================================
# 4. HÀM ĐIỀU PHỐI: Chọn thuật toán theo lựa chọn người dùng
#    (dùng để nối với giao diện web - dropdown chọn thuật toán)
# ============================================================
def ma_hoa(van_ban_goc, mat_khau, thuat_toan="AES"):
    """
    thuat_toan: "AES" hoặc "CHACHA20"
    """
    thuat_toan = thuat_toan.upper()
    if thuat_toan == "AES":
        return ma_hoa_aes(van_ban_goc, mat_khau)
    elif thuat_toan == "CHACHA20":
        return ma_hoa_chacha20(van_ban_goc, mat_khau)
    else:
        raise ValueError(f"Thuật toán '{thuat_toan}' không được hỗ trợ.")


def giai_ma(chuoi_base64, mat_khau, thuat_toan="AES"):
    """
    thuat_toan: "AES" hoặc "CHACHA20"
    """
    thuat_toan = thuat_toan.upper()
    if thuat_toan == "AES":
        return giai_ma_aes(chuoi_base64, mat_khau)
    elif thuat_toan == "CHACHA20":
        return giai_ma_chacha20(chuoi_base64, mat_khau)
    else:
        raise ValueError(f"Thuật toán '{thuat_toan}' không được hỗ trợ.")


# ============================================================
# CHẠY THỬ (chỉ chạy khi thực thi trực tiếp file này)
# ============================================================
if __name__ == "__main__":
    van_ban = "Day la watermark bi mat"
    khoa_nguoi_dung = "matkhau123"

    print("--- Kiểm thử AES-GCM ---")
    ma = ma_hoa(van_ban, khoa_nguoi_dung, "AES")
    print("Bản mã (base64):", ma)
    goc = giai_ma(ma, khoa_nguoi_dung, "AES")
    print("Giải mã lại:", goc)
    print("Khớp với bản gốc:", goc == van_ban)

    print("\n--- Kiểm thử ChaCha20 ---")
    ma2 = ma_hoa(van_ban, khoa_nguoi_dung, "CHACHA20")
    print("Bản mã (base64):", ma2)
    goc2 = giai_ma(ma2, khoa_nguoi_dung, "CHACHA20")
    print("Giải mã lại:", goc2)
    print("Khớp với bản gốc:", goc2 == van_ban)

    print("\n--- Kiểm thử sai khóa (phải báo lỗi) ---")
    giai_ma(ma, "sai_khoa", "AES")

    print("\n--- Kiểm thử RSA ---")
    cong_khai, rieng_tu = tao_cap_khoa_rsa(2048)
    print("Đã sinh cặp khóa RSA 2048-bit.")
    ma_rsa = ma_hoa_rsa(van_ban, cong_khai)
    print("Bản mã RSA (base64):", ma_rsa)
    goc_rsa = giai_ma_rsa(ma_rsa, rieng_tu)
    print("Giải mã lại:", goc_rsa)
    print("Khớp với bản gốc:", goc_rsa == van_ban)

    print("\n--- Kiểm thử mô hình lai (RSA mã hóa khóa AES) ---")
    khoa_aes_ngau_nhien = get_random_bytes(32)
    khoa_da_ma_hoa = rsa_ma_hoa_khoa_doi_xung(khoa_aes_ngau_nhien, cong_khai)
    khoa_giai_ma_lai = rsa_giai_ma_khoa_doi_xung(khoa_da_ma_hoa, rieng_tu)
    print("Khóa AES khớp sau khi giải mã bằng RSA:", khoa_aes_ngau_nhien == khoa_giai_ma_lai)
