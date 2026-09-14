"""
Backend xử lý nhúng/trích xuất watermark bằng kỹ thuật LSB (Least Significant Bit).
"""
 
import math
from PIL import Image
from thuat_toan_ma_hoa import ky_so_rsa, kiem_tra_ky_so_rsa
 
 
def kiem_tra_suc_chua(anh_goc, encrypt):
    """
    Kiểm tra ảnh có đủ dung lượng để nhúng bản mã.
    
    Args:
        anh_goc: BytesIO hoặc file ảnh
        encrypt: bản mã (str)
    
    Returns:
        True nếu đủ dung lượng, False nếu không
    """
    img = Image.open(anh_goc)
    rong, cao = img.size
    
    # Số bit có thể giấu: 3 bit/pixel (RGB), mỗi byte 8 bit
    suc_chua_bits = rong * cao * 3
    
    # Dữ liệu cần giấu: bản mã + 16 bit ngắt
    du_lieu_bits = len(encrypt.encode('utf-8')) * 8 + 16
    
    return du_lieu_bits <= suc_chua_bits
 
 
def nhung_thong_diep(anh_goc, anh_dich, encrypt):
    """
    Nhúng thông điệp (bản mã) vào ảnh bằng LSB.
    
    Args:
        anh_goc: BytesIO ảnh gốc
        anh_dich: BytesIO kết quả (sẽ ghi ảnh PNG)
        encrypt: bản mã (str - chuỗi Base64 từ mã hóa)
    """
    if not kiem_tra_suc_chua(anh_goc, encrypt):
        raise ValueError("Ảnh không đủ dung lượng để nhúng bản mã")
    
    img = Image.open(anh_goc).convert('RGB')
    pixels = list(img.getdata())
    
    # Chuyển bản mã sang chuỗi bit, thêm 16 bit ngắt ở cuối
    chuoi_bit = ''.join(format(ord(c), '08b') for c in encrypt) + '1111111111111110'
    
    idx = 0
    new_pixels = []
    
    for r, g, b in pixels:
        kenh_mau = [r, g, b]
        for i in range(3):
            if idx < len(chuoi_bit):
                bit = int(chuoi_bit[idx])
                kenh_mau[i] = (kenh_mau[i] & ~1) | bit
                idx += 1
        new_pixels.append(tuple(kenh_mau))
    
    img_moi = Image.new(img.mode, img.size)
    img_moi.putdata(new_pixels)
    img_moi.save(anh_dich, 'PNG')
 
 
def trich_xuat_thong_diep(anh_da_nhung):
    """
    Trích xuất thông điệp từ ảnh bằng LSB.
    
    Đọc lại chuỗi bit, dừng khi gặp ký hiệu ngắt '1111111111111110'.
    
    Args:
        anh_da_nhung: BytesIO ảnh đã nhúng
    
    Returns:
        Bản mã (str) hoặc None nếu không tìm thấy
    """
    img = Image.open(anh_da_nhung).convert('RGB')
    pixels = list(img.getdata())
    
    chuoi_bit = ""
    ky_hieu_ngat = "1111111111111110"
    
    for r, g, b in pixels:
        for kenh in (r, g, b):
            chuoi_bit += str(kenh & 1)
            if chuoi_bit.endswith(ky_hieu_ngat):
                # Bỏ ký hiệu ngắt, chuyển bit thành văn bản
                chuoi_bit = chuoi_bit[:-len(ky_hieu_ngat)]
                van_ban = "".join(
                    chr(int(chuoi_bit[i:i + 8], 2))
                    for i in range(0, len(chuoi_bit), 8)
                )
                return van_ban
    
    return None
 
 
def nhung_voi_chu_ky(anh_goc, anh_dich, watermark_da_ma_hoa, khoa_rieng_tu_rsa):
    """
    Nhúng watermark + chữ ký số RSA vào ảnh.
    
    Cấu trúc: watermark_da_ma_hoa + "|" + chu_ky_rsa_base64
    
    Args:
        anh_goc: BytesIO ảnh gốc
        anh_dich: BytesIO kết quả
        watermark_da_ma_hoa: bản mã Base64
        khoa_rieng_tu_rsa: khóa riêng tư PEM để ký
    """
    # Ký watermark bằng RSA
    chu_ky = ky_so_rsa(watermark_da_ma_hoa, khoa_rieng_tu_rsa)
    
    # Gộp bản mã + chữ ký
    du_lieu_gop = f"{watermark_da_ma_hoa}|{chu_ky}"
    
    # Nhúng vào ảnh
    nhung_thong_diep(anh_goc, anh_dich, du_lieu_gop)
 
 
def trich_xuat_va_kiem_tra_chu_ky(anh_da_nhung, khoa_cong_khai_rsa):
    """
    Trích xuất watermark và xác minh chữ ký RSA.
    
    Returns:
        (watermark_da_ma_hoa, kem_theo_chu_ky) 
        - watermark_da_ma_hoa: bản mã nếu chữ ký hợp lệ, None nếu lỗi
        - kem_theo_chu_ky: True nếu chứa chữ ký, False nếu không
    """
    du_lieu = trich_xuat_thong_diep(anh_da_nhung)
    
    if du_lieu is None:
        return None, False
    
    # Kiểm tra có chữ ký không (định dạng: "bản_mã|chữ_ký")
    if '|' not in du_lieu:
        return du_lieu, False
    
    watermark_da_ma_hoa, chu_ky = du_lieu.rsplit('|', 1)
    
    # Xác minh chữ ký
    hop_le = kiem_tra_ky_so_rsa(watermark_da_ma_hoa, chu_ky, khoa_cong_khai_rsa)
    
    if hop_le:
        return watermark_da_ma_hoa, True
    else:
        return None, False


def tinh_psnr(anh_goc, anh_da_nhung):
    """
    Tính PSNR (Peak Signal-to-Noise Ratio) giữa ảnh gốc và ảnh đã nhúng watermark,
    dùng để đánh giá mức độ "vô hình" của watermark: PSNR càng cao thì sai khác
    giữa hai ảnh càng khó nhận biết bằng mắt thường.

    Công thức: PSNR = 10 * log10(MAX^2 / MSE), với MAX = 255 (ảnh 8-bit/kênh)
    và MSE là sai số bình phương trung bình trên cả 3 kênh màu RGB.

    Args:
        anh_goc: BytesIO hoặc file ảnh gốc (trước khi nhúng)
        anh_da_nhung: BytesIO hoặc file ảnh sau khi nhúng watermark

    Returns:
        PSNR tính bằng dB (float),
        float('inf') nếu hai ảnh giống hệt nhau (không có sai khác),
        hoặc None nếu kích thước hai ảnh không khớp (không thể so sánh)
    """
    img1 = Image.open(anh_goc).convert('RGB')
    img2 = Image.open(anh_da_nhung).convert('RGB')

    if img1.size != img2.size:
        return None

    pixels1 = img1.getdata()
    pixels2 = img2.getdata()

    tong_binh_phuong_loi = 0
    so_gia_tri = img1.size[0] * img1.size[1] * 3  # 3 kênh RGB

    for (r1, g1, b1), (r2, g2, b2) in zip(pixels1, pixels2):
        tong_binh_phuong_loi += (r1 - r2) ** 2 + (g1 - g2) ** 2 + (b1 - b2) ** 2

    if tong_binh_phuong_loi == 0:
        return float('inf')

    mse = tong_binh_phuong_loi / so_gia_tri
    MAX_GIA_TRI_PIXEL = 255.0

    return 10 * math.log10((MAX_GIA_TRI_PIXEL ** 2) / mse)


def danh_gia_psnr(psnr):
    """
    Trả về đánh giá định tính (chuỗi mô tả) cho một giá trị PSNR (dB), theo các
    ngưỡng phổ biến trong watermarking ảnh.

    Args:
        psnr: giá trị PSNR (float), hoặc None, hoặc float('inf')

    Returns:
        Chuỗi mô tả mức độ "vô hình" của watermark
    """
    if psnr is None:
        return "Không thể đánh giá (kích thước ảnh không khớp)."
    if psnr == float('inf'):
        return "Hai ảnh giống hệt nhau (không phát hiện sai khác)."
    if psnr >= 40:
        return "Rất tốt — watermark gần như không thể nhận biết bằng mắt thường."
    if psnr >= 30:
        return "Tốt — watermark khó nhận biết bằng mắt thường."
    if psnr >= 20:
        return "Trung bình — có thể nhận thấy sai khác nhẹ khi quan sát kỹ."
    return "Kém — sai khác dễ nhận biết bằng mắt thường."