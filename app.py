import io
import time
import traceback
from flask import Flask, request, jsonify, send_file, render_template
 
from backend import (
    nhung_thong_diep,
    trich_xuat_thong_diep,
    kiem_tra_suc_chua,
    trich_xuat_va_kiem_tra_chu_ky,
    tinh_psnr,
    danh_gia_psnr,
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
        
        # Tính PSNR giữa ảnh gốc và ảnh đã nhúng để đánh giá mức độ "vô hình"
        # của watermark, trả về trong header để client không cần gọi thêm request.
        psnr = tinh_psnr(io.BytesIO(du_lieu_anh), io.BytesIO(buffer_dich.getvalue()))
        buffer_dich.seek(0)
        
        response = send_file(
            buffer_dich,
            mimetype="image/png",
            as_attachment=True,
            download_name="anh_da_nhung_watermark.png"
        )
        if psnr is not None:
            response.headers["X-PSNR-DB"] = "inf" if psnr == float("inf") else f"{psnr:.2f}"
            response.headers["Access-Control-Expose-Headers"] = "X-PSNR-DB"
        return response
    
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
 
 
@app.route("/api/so-sanh-thuat-toan", methods=["POST"])
def api_so_sanh_thuat_toan():
    """
    So sánh thời gian mã hóa/giải mã của AES, ChaCha20 và RSA trên cùng một
    đoạn văn bản, để thấy trực quan sự khác biệt tốc độ giữa các thuật toán.

    Body JSON:
      - van_ban: đoạn văn bản dùng để đo (bắt buộc)
      - khoa: mật khẩu dùng cho AES/ChaCha20 (tùy chọn, mặc định "khoa-demo-so-sanh")
      - do_dai_bit_rsa: độ dài khóa RSA tính bằng bit (tùy chọn, mặc định 2048)
      - so_lan_lap: số lần lặp để lấy trung bình, giúp kết quả ổn định hơn
        (tùy chọn, mặc định 10, tối đa 1000)

    Response JSON:
      {
        "thanh_cong": true,
        "do_dai_van_ban": <số byte UTF-8>,
        "so_lan_lap": <int>,
        "ket_qua": {
          "AES":      {"thanh_cong": true, "thoi_gian_ma_hoa_ms": ..., "thoi_gian_giai_ma_ms": ...},
          "CHACHA20": {"thanh_cong": true, "thoi_gian_ma_hoa_ms": ..., "thoi_gian_giai_ma_ms": ...},
          "RSA":      {"thanh_cong": true, "do_dai_bit": ..., "thoi_gian_tao_khoa_ms": ...,
                       "thoi_gian_ma_hoa_ms": ..., "thoi_gian_giai_ma_ms": ...}
        }
      }
    """
    try:
        du_lieu = request.get_json(silent=True) or {}
        van_ban = du_lieu.get("van_ban")
        khoa = du_lieu.get("khoa") or "khoa-demo-so-sanh"
        do_dai_bit_rsa = int(du_lieu.get("do_dai_bit_rsa", 2048))
        so_lan_lap = int(du_lieu.get("so_lan_lap", 10))

        if not van_ban:
            return jsonify({"thanh_cong": False, "loi": "Thiếu văn bản để so sánh."}), 400
        if so_lan_lap < 1 or so_lan_lap > 1000:
            return jsonify({"thanh_cong": False, "loi": "so_lan_lap phải trong khoảng 1-1000."}), 400

        ket_qua = {}

        # ---- AES ----
        try:
            t0 = time.perf_counter()
            for _ in range(so_lan_lap):
                ban_ma_aes = ma_hoa_aes(van_ban, khoa)
            t1 = time.perf_counter()
            for _ in range(so_lan_lap):
                giai_ma_aes(ban_ma_aes, khoa)
            t2 = time.perf_counter()
            ket_qua["AES"] = {
                "thanh_cong": True,
                "thoi_gian_ma_hoa_ms": round((t1 - t0) / so_lan_lap * 1000, 4),
                "thoi_gian_giai_ma_ms": round((t2 - t1) / so_lan_lap * 1000, 4),
            }
        except Exception as loi:
            ket_qua["AES"] = {"thanh_cong": False, "loi": str(loi)}

        # ---- ChaCha20 ----
        try:
            t0 = time.perf_counter()
            for _ in range(so_lan_lap):
                ban_ma_cc = ma_hoa_chacha20(van_ban, khoa)
            t1 = time.perf_counter()
            for _ in range(so_lan_lap):
                giai_ma_chacha20(ban_ma_cc, khoa)
            t2 = time.perf_counter()
            ket_qua["CHACHA20"] = {
                "thanh_cong": True,
                "thoi_gian_ma_hoa_ms": round((t1 - t0) / so_lan_lap * 1000, 4),
                "thoi_gian_giai_ma_ms": round((t2 - t1) / so_lan_lap * 1000, 4),
            }
        except Exception as loi:
            ket_qua["CHACHA20"] = {"thanh_cong": False, "loi": str(loi)}

        # ---- RSA ---- (đo riêng thời gian tạo khóa, vì đây là bước tốn thời gian nhất)
        try:
            t0 = time.perf_counter()
            khoa_cong_khai, khoa_rieng_tu = tao_cap_khoa_rsa(do_dai_bit_rsa)
            t1 = time.perf_counter()

            for _ in range(so_lan_lap):
                ban_ma_rsa = ma_hoa_rsa(van_ban, khoa_cong_khai)
            t2 = time.perf_counter()
            for _ in range(so_lan_lap):
                giai_ma_rsa(ban_ma_rsa, khoa_rieng_tu)
            t3 = time.perf_counter()

            ket_qua["RSA"] = {
                "thanh_cong": True,
                "do_dai_bit": do_dai_bit_rsa,
                "thoi_gian_tao_khoa_ms": round((t1 - t0) * 1000, 4),
                "thoi_gian_ma_hoa_ms": round((t2 - t1) / so_lan_lap * 1000, 4),
                "thoi_gian_giai_ma_ms": round((t3 - t2) / so_lan_lap * 1000, 4),
            }
        except Exception as loi:
            # RSA thường giới hạn độ dài văn bản có thể mã hóa trực tiếp theo độ dài khóa
            ket_qua["RSA"] = {
                "thanh_cong": False,
                "loi": f"{loi} (RSA giới hạn độ dài văn bản mã hóa trực tiếp theo độ dài khóa "
                       f"— thử văn bản ngắn hơn hoặc tăng do_dai_bit_rsa)."
            }

        return jsonify({
            "thanh_cong": True,
            "do_dai_van_ban": len(van_ban.encode("utf-8")),
            "so_lan_lap": so_lan_lap,
            "ket_qua": ket_qua
        })

    except Exception:
        return jsonify({"thanh_cong": False, "loi": traceback.format_exc()}), 500


@app.route("/api/psnr", methods=["POST"])
def api_tinh_psnr():
    """
    Tính PSNR (Peak Signal-to-Noise Ratio) giữa ảnh gốc và ảnh đã nhúng watermark,
    để đánh giá mức độ "vô hình" của watermark — PSNR càng cao, watermark càng
    khó nhận biết bằng mắt thường.

    Lưu ý: nếu chỉ vừa nhúng watermark qua /api/nhung, giá trị PSNR đã có sẵn
    trong header "X-PSNR-DB" của response đó, không cần gọi endpoint này thêm.
    Endpoint này hữu ích khi bạn muốn so sánh hai ảnh bất kỳ đã có sẵn.

    Form data:
      - anh_goc: file ảnh gốc (bắt buộc)
      - anh_da_nhung: file ảnh đã nhúng watermark (bắt buộc)

    Response JSON:
      { "thanh_cong": true, "psnr_db": <float|null>, "vo_han": <bool>, "danh_gia": "..." }
      (psnr_db là null khi hai ảnh giống hệt nhau — xem trường "vo_han")
    """
    try:
        if "anh_goc" not in request.files or "anh_da_nhung" not in request.files:
            return jsonify({
                "thanh_cong": False,
                "loi": "Thiếu file 'anh_goc' hoặc 'anh_da_nhung'."
            }), 400

        du_lieu_anh_goc = request.files["anh_goc"].read()
        du_lieu_anh_nhung = request.files["anh_da_nhung"].read()

        psnr = tinh_psnr(io.BytesIO(du_lieu_anh_goc), io.BytesIO(du_lieu_anh_nhung))

        if psnr is None:
            return jsonify({
                "thanh_cong": False,
                "loi": "Kích thước hai ảnh không khớp, không thể tính PSNR."
            }), 400

        return jsonify({
            "thanh_cong": True,
            "psnr_db": None if psnr == float("inf") else round(psnr, 2),
            "vo_han": psnr == float("inf"),
            "danh_gia": danh_gia_psnr(psnr)
        })

    except Exception:
        return jsonify({"thanh_cong": False, "loi": traceback.format_exc()}), 500


if __name__ == "__main__":
    app.run(debug=True, port=5000)