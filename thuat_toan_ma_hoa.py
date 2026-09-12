"""
Các thuật toán mã hóa/giải mã cho hệ thống Thủy vân số (Watermarking).
Hỗ trợ: AES-GCM, ChaCha20, RSA (với chữ ký số)
"""
 
import base64
from Crypto.Cipher import AES, ChaCha20, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
 
 
def tao_khoa_tu_mat_khau(mat_khau, salt, do_dai_khoa=32, vong_lap=100_000):
    """
    Sinh khóa nhị phân từ mật khẩu người dùng bằng PBKDF2.
    
    Args:
        mat_khau: chuỗi mật khẩu (str)
        salt: bytes ngẫu nhiên (nên lưu kèm bản mã)
        do_dai_khoa: độ dài khóa output (byte, mặc định 32 = 256-bit)
        vong_lap: số vòng PBKDF2 (mặc định 100,000)
    
    Returns:
        khóa nhị phân (bytes, 32 byte)
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
# AES-GCM (mã hóa đối xứng với xác thực)
# ============================================================
def ma_hoa_aes(van_ban_goc, mat_khau):
    """
    Mã hóa AES-GCM.
    
    Returns:
        Base64(salt + nonce + tag + bản mã)
    """
    salt = get_random_bytes(16)
    khoa = tao_khoa_tu_mat_khau(mat_khau, salt)
    cipher = AES.new(khoa, AES.MODE_GCM)
    ban_ma, tag = cipher.encrypt_and_digest(van_ban_goc.encode('utf-8'))
    
    du_lieu_gop = salt + cipher.nonce + tag + ban_ma
    return base64.b64encode(du_lieu_gop).decode('utf-8')
 
 
def giai_ma_aes(chuoi_base64, mat_khau):
    """
    Giải mã AES-GCM.
    
    Returns:
        Văn bản gốc (str) hoặc None nếu lỗi
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
        return None
 
 
# ============================================================
# ChaCha20 (mã hóa dòng)
# ============================================================
def ma_hoa_chacha20(van_ban_goc, mat_khau):
    """
    Mã hóa ChaCha20.
    
    Returns:
        Base64(salt + nonce + bản mã)
    """
    salt = get_random_bytes(16)
    khoa = tao_khoa_tu_mat_khau(mat_khau, salt)
    cipher = ChaCha20.new(key=khoa)
    ban_ma = cipher.encrypt(van_ban_goc.encode('utf-8'))
    
    du_lieu_gop = salt + cipher.nonce + ban_ma
    return base64.b64encode(du_lieu_gop).decode('utf-8')
 
 
def giai_ma_chacha20(chuoi_base64, mat_khau):
    """
    Giải mã ChaCha20.
    
    Returns:
        Văn bản gốc (str) hoặc None nếu lỗi
    """
    try:
        du_lieu_gop = base64.b64decode(chuoi_base64)
        salt = du_lieu_gop[:16]
        nonce = du_lieu_gop[16:24]
        ban_ma = du_lieu_gop[24:]
        
        khoa = tao_khoa_tu_mat_khau(mat_khau, salt)
        cipher = ChaCha20.new(key=khoa, nonce=nonce)
        van_ban_goc = cipher.decrypt(ban_ma)
        
        return van_ban_goc.decode('utf-8')
    except (ValueError, UnicodeDecodeError):
        return None
 
 
# ============================================================
# RSA (mã hóa bất đối xứng + chữ ký số)
# ============================================================
def tao_cap_khoa_rsa(do_dai_bit=2048):
    """
    Sinh cặp khóa RSA.
    
    Args:
        do_dai_bit: độ dài khóa (mặc định 2048)
    
    Returns:
        (khóa công khai PEM, khóa riêng tư PEM) - cả hai dạng str
    """
    khoa = RSA.generate(do_dai_bit)
    khoa_rieng_tu_pem = khoa.export_key().decode('utf-8')
    khoa_cong_khai_pem = khoa.publickey().export_key().decode('utf-8')
    return khoa_cong_khai_pem, khoa_rieng_tu_pem
 
 
def ma_hoa_rsa(van_ban_goc, khoa_cong_khai_pem):
    """
    Mã hóa RSA-OAEP.
    
    Lưu ý: RSA chỉ mã hóa được ~190 byte (với khóa 2048-bit).
    Để mã hóa watermark dài, sử dụng AES/ChaCha20 thay thế.
    
    Returns:
        Base64 bản mã
    """
    khoa_cong_khai = RSA.import_key(khoa_cong_khai_pem)
    cipher = PKCS1_OAEP.new(khoa_cong_khai)
    ban_ma = cipher.encrypt(van_ban_goc.encode('utf-8'))
    return base64.b64encode(ban_ma).decode('utf-8')
 
 
def giai_ma_rsa(chuoi_base64, khoa_rieng_tu_pem):
    """
    Giải mã RSA-OAEP.
    
    Returns:
        Văn bản gốc (str) hoặc None nếu lỗi
    """
    try:
        khoa_rieng_tu = RSA.import_key(khoa_rieng_tu_pem)
        cipher = PKCS1_OAEP.new(khoa_rieng_tu)
        ban_ma = base64.b64decode(chuoi_base64)
        van_ban_goc = cipher.decrypt(ban_ma)
        return van_ban_goc.decode('utf-8')
    except (ValueError, TypeError):
        return None
 
 
def ky_so_rsa(du_lieu, khoa_rieng_tu_pem):
    """
    Ký dữ liệu bằng RSA-SHA256 (PKCS#1 v1.5).
    
    Args:
        du_lieu: dữ liệu cần ký (str hoặc bytes)
        khoa_rieng_tu_pem: khóa riêng tư PEM
    
    Returns:
        Base64 chữ ký
    """
    if isinstance(du_lieu, str):
        du_lieu = du_lieu.encode('utf-8')
    
    khoa_rieng_tu = RSA.import_key(khoa_rieng_tu_pem)
    h = SHA256.new(du_lieu)
    ky_so = pkcs1_15.new(khoa_rieng_tu).sign(h)
    return base64.b64encode(ky_so).decode('utf-8')
 
 
def kiem_tra_ky_so_rsa(du_lieu, chuoi_ky_so_base64, khoa_cong_khai_pem):
    """
    Xác minh chữ ký RSA-SHA256.
    
    Args:
        du_lieu: dữ liệu gốc (str hoặc bytes)
        chuoi_ky_so_base64: chữ ký dạng Base64
        khoa_cong_khai_pem: khóa công khai PEM
    
    Returns:
        True nếu chữ ký hợp lệ, False nếu không
    """
    try:
        if isinstance(du_lieu, str):
            du_lieu = du_lieu.encode('utf-8')
        
        khoa_cong_khai = RSA.import_key(khoa_cong_khai_pem)
        h = SHA256.new(du_lieu)
        ky_so = base64.b64decode(chuoi_ky_so_base64)
        pkcs1_15.new(khoa_cong_khai).verify(h, ky_so)
        return True
    except (ValueError, TypeError):
        return False