import io
import traceback
from flask import Flask, request, jsonify, send_file, render_template
 
from backend import (
    nhung_thong_diep,
    trich_xuat_thong_diep,
    kiem_tra_suc_chua,
    trich_xuat_va_kiem_tra_chu_ky,
)
from thuat_toan_ma_hoa import (
    ma_hoa_aes, giai_ma_aes,
    ma_hoa_chacha20, giai_ma_chacha20,
    ma_hoa_rsa, giai_ma_rsa,
    tao_cap_khoa_rsa,
    ky_so_rsa,
)
 
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB
 
THUAT_TOAN_HOP_LE = {"AES", "CHACHA20", "RSA"}
 
 
@app.route("/", methods=["GET"])
def trang_chu():
    return render_template("index.html"), 200, {"Content-Type": "text/html; charset=utf-8"}
 
 
@app.route("/api/rsa/tao-khoa", methods=["POST"])
def api_tao_khoa_rsa():
    """
    Tạo cặp khóa RSA.
    
    Body JSON (tùy chọn): { "do_dai_bit": 2048 }
    Response: { "thanh_cong": true, "khoa_cong_khai": "...", "khoa_rieng_tu": "..." }
    """
    try:
        du_lieu = request.get_json(silent=True) or {}
        do_dai_bit = int(du_lieu.get("do_dai_bit", 2048))
        
        khoa_cong_khai, khoa_rieng_tu = tao_cap_khoa_rsa(do_dai_bit)
        
        return jsonify({
            "thanh_cong": True,
            "khoa_cong_khai": khoa_cong_khai,
            "khoa_rieng_tu": khoa_rieng_tu
        })
    except Exception as loi:
        return jsonify({"thanh_cong": False, "loi": str(loi)}), 400
 
 
@app.route("/api/nhung", methods=["POST"])
def api_nhung_watermark():
    """
    Mã hóa + Nhúng watermark vào ảnh.
    
    Form data:
      - anh: file ảnh (bắt buộc)
      - watermark: nội dung (bắt buộc)
      - thuat_toan: AES | CHACHA20 | RSA (bắt buộc)
      - khoa: mật khẩu (AES/ChaCha20) hoặc khóa công khai PEM (RSA) (bắt buộc)
      - khoa_rieng_tu_rsa: khóa riêng tư PEM (tùy chọn, để ký chữ ký khi dùng RSA)
    
    Response: file PNG đã nhúng watermark
    """
    try:
        if "anh" not in request.files:
            return jsonify({"thanh_cong": False, "loi": "Thiếu file ảnh."}), 400
        
        file_anh = request.files["anh"]
        watermark = request.form.get("watermark")
        thuat_toan = (request.form.get("thuat_toan") or "").upper()
        khoa = request.form.get("khoa")
        khoa_rieng_tu_rsa = request.form.get("khoa_rieng_tu_rsa")
        
        if not watermark:
            return jsonify({"thanh_cong": False, "loi": "Thiếu watermark."}), 400
        if thuat_toan not in THUAT_TOAN_HOP_LE:
            return jsonify({"thanh_cong": False, "loi": f"Thuật toán phải là: {THUAT_TOAN_HOP_LE}"}), 400
        if not khoa:
            return jsonify({"thanh_cong": False, "loi": "Thiếu khóa."}), 400
        
        du_lieu_anh = file_anh.read()
        
        # Mã hóa watermark
        if thuat_toan == "AES":
            ban_ma = ma_hoa_aes(watermark, khoa)
        elif thuat_toan == "CHACHA20":
            ban_ma = ma_hoa_chacha20(watermark, khoa)
        else:  # RSA
            ban_ma = ma_hoa_rsa(watermark, khoa)
        
        # Nếu là RSA và có khóa riêng tư, ký TRƯỚC để dữ liệu thực sự sẽ nhúng
        # (bản mã + "|" + chữ ký) được biết đầy đủ trước khi kiểm tra dung lượng.
        du_lieu_de_nhung = ban_ma
        co_chu_ky = False
        if thuat_toan == "RSA" and khoa_rieng_tu_rsa:
            try:
                chu_ky = ky_so_rsa(ban_ma, khoa_rieng_tu_rsa)
            except (ValueError, TypeError):
                return jsonify({
                    "thanh_cong": False,
                    "loi": "Khóa riêng tư RSA không hợp lệ, không thể ký chữ ký số."
                }), 400
            du_lieu_de_nhung = f"{ban_ma}|{chu_ky}"
            co_chu_ky = True
        
        # Kiểm tra dung lượng trên đúng dữ liệu sẽ nhúng (bao gồm cả chữ ký nếu có)
        if not kiem_tra_suc_chua(io.BytesIO(du_lieu_anh), du_lieu_de_nhung):
            return jsonify({
                "thanh_cong": False,
                "loi": "Ảnh không đủ dung lượng để nhúng watermark"
                       + (" kèm chữ ký số RSA (chữ ký chiếm thêm dung lượng đáng kể — thử ảnh lớn hơn)" if co_chu_ky else "")
                       + "."
            }), 400
        
        # Nhúng
        buffer_dich = io.BytesIO()
        nhung_thong_diep(io.BytesIO(du_lieu_anh), buffer_dich, du_lieu_de_nhung)
        buffer_dich.seek(0)
        
        return send_file(
            buffer_dich,
            mimetype="image/png",
            as_attachment=True,
            download_name="anh_da_nhung_watermark.png"
        )
    
    except Exception:
        return jsonify({"thanh_cong": False, "loi": traceback.format_exc()}), 500
 
 
@app.route("/api/trich-xuat", methods=["POST"])
def api_trich_xuat_watermark():
    """
    Trích xuất + Giải mã watermark từ ảnh.
    
    Form data:
      - anh: file ảnh đã nhúng (bắt buộc)
      - thuat_toan: AES | CHACHA20 | RSA (bắt buộc)
      - khoa: mật khẩu (AES/ChaCha20) hoặc khóa riêng tư PEM (RSA) (bắt buộc)
      - khoa_cong_khai_rsa: khóa công khai PEM (tùy chọn, để xác minh chữ ký RSA)
    
    Response JSON: { "thanh_cong": true, "watermark": "...", "chu_ky_hop_le": true|false }
    """
    try:
        if "anh" not in request.files:
            return jsonify({"thanh_cong": False, "loi": "Thiếu file ảnh."}), 400
        
        file_anh = request.files["anh"]
        thuat_toan = (request.form.get("thuat_toan") or "").upper()
        khoa = request.form.get("khoa")
        khoa_cong_khai_rsa = request.form.get("khoa_cong_khai_rsa")
        
        if thuat_toan not in THUAT_TOAN_HOP_LE:
            return jsonify({"thanh_cong": False, "loi": f"Thuật toán phải là: {THUAT_TOAN_HOP_LE}"}), 400
        if not khoa:
            return jsonify({"thanh_cong": False, "loi": "Thiếu khóa."}), 400
        
        du_lieu_anh = file_anh.read()
        
        # Trích xuất từ ảnh
        ban_ma = trich_xuat_thong_diep(io.BytesIO(du_lieu_anh))
        if ban_ma is None:
            return jsonify({"thanh_cong": False, "loi": "Không tìm thấy watermark trong ảnh."}), 400
        
        # Với RSA: dữ liệu có thể là "bản_mã" (không ký) hoặc "bản_mã|chữ_ký" (có ký).
        # co_chu_ky: ảnh có mang chữ ký hay không.
        # chu_ky_hop_le: True nếu đã xác minh và hợp lệ; None nếu không thể/không xác minh
        #   (không có chữ ký, hoặc có chữ ký nhưng chưa nhập khóa công khai để kiểm tra).
        co_chu_ky = (thuat_toan == "RSA" and '|' in ban_ma)
        chu_ky_hop_le = None
        
        if co_chu_ky:
            if khoa_cong_khai_rsa:
                ban_ma, hop_le = trich_xuat_va_kiem_tra_chu_ky(
                    io.BytesIO(du_lieu_anh),
                    khoa_cong_khai_rsa
                )
                if ban_ma is None:
                    return jsonify({
                        "thanh_cong": False,
                        "loi": "Chữ ký không hợp lệ hoặc dữ liệu bị thay đổi."
                    }), 400
                chu_ky_hop_le = hop_le  # True
            else:
                # Không có khóa công khai để xác minh: vẫn giải mã được bản mã,
                # chỉ bỏ qua bước xác minh (không coi đây là lỗi).
                ban_ma = ban_ma.rsplit('|', 1)[0]
        
        # Giải mã
        if thuat_toan == "AES":
            watermark = giai_ma_aes(ban_ma, khoa)
        elif thuat_toan == "CHACHA20":
            watermark = giai_ma_chacha20(ban_ma, khoa)
        else:  # RSA
            watermark = giai_ma_rsa(ban_ma, khoa)
        
        if watermark is None:
            return jsonify({"thanh_cong": False, "loi": "Sai khóa hoặc dữ liệu bị hỏng."}), 400
        
        response = {
            "thanh_cong": True,
            "watermark": watermark
        }
        
        if thuat_toan == "RSA":
            response["co_chu_ky"] = co_chu_ky
            response["chu_ky_hop_le"] = chu_ky_hop_le
        
        return jsonify(response)
    
    except Exception:
        return jsonify({"thanh_cong": False, "loi": traceback.format_exc()}), 500
 
 
if __name__ == "__main__":
    app.run(debug=True, port=5000)