from PIL import Image

def kiem_tra_suc_chua(anh_goc, van_ban):
    img = Image.open(anh_goc)
    rong, cao = img.size
    
    # 1. Tính tổng số bit ảnh có thể giấu (RGB = 3 bit/pixel)
    tong_pixel = rong * cao
    suc_chua_bits = tong_pixel * 3
    suc_chua_bytes = suc_chua_bits // 8
    
    # 2. Tính số bit của thông điệp (+ 16 bit ngắt)
    do_dai_van_ban_bits = len(van_ban.encode('utf-8')) * 8 + 16
    
    # 3. In thông báo chi tiết
    print(f"--- THÔNG TIN DUNG LƯỢNG ---")
    print(f"Kích thước ảnh: {rong}x{cao} ({tong_pixel:,} pixels)")
    print(f"Sức chứa tối đa: {suc_chua_bytes:,} Bytes (~{suc_chua_bytes/1024:.2f} KB)")
    print(f"Độ dài thông điệp: {len(van_ban)} ký tự ({do_dai_van_ban_bits} bits)")
    
    # 4. Trả về True nếu chứa đủ, False nếu không đủ
    if do_dai_van_ban_bits <= suc_chua_bits:
        print("=> Kết quả: DỦ DUNG LƯỢNG để nhúng.\n")
        return True
    else:
        print("=> Kết quả: KHÔNG ĐỦ DUNG LƯỢNG!\n")
        return False


def nhung_thong_diep(anh_goc, anh_dich, van_ban):
    # Kiểm tra độ dài trước khi xử lý
    if not kiem_tra_suc_chua(anh_goc, van_ban):
        print("Hủy quá trình nhúng do thông điệp quá dài!")
        return

    img = Image.open(anh_goc).convert('RGB')
    pixels = list(img.getdata())
    
    # Chuyển văn bản sang chuỗi bit (kèm 16 bit '1' ngắt đuôi)
    chuoi_bit = ''.join(format(ord(c), '08b') for c in van_ban) + '1111111111111110'
    
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
    print("Đã nhúng thông điệp thành công!")