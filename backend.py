"""
Backend xử lý nhúng/trích xuất watermark bằng kỹ thuật LSB (Least Significant Bit).
"""
 
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
 