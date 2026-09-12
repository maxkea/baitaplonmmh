"""
app.py - API backend cho hệ thống Thủy vân số (Watermarking) bằng LSB + Mã hóa
Chạy: python app.py  (mặc định chạy ở http://127.0.0.1:5000)

Danh sách endpoint:
  POST /api/rsa/tao-khoa      -> Sinh cặp khóa RSA
  POST /api/nhung             -> Mã hóa watermark + nhúng vào ảnh, trả về ẢNH đã nhúng
  POST /api/trich-xuat        -> Đọc ảnh đã nhúng, giải mã, trả về watermark gốc (JSON)

Không có giao diện HTML - chỉ là API (dùng Postman / fetch / curl để gọi).
"""

import io
import traceback
from flask import Flask, request, jsonify, send_file, render_template

from backend import (
    nhung_thong_diep,
    trich_xuat_thong_diep,
    kiem_tra_suc_chua,
)
from thuat_toan_ma_hoa import (
    ma_hoa_aes, giai_ma_aes,
    ma_hoa_chacha20, giai_ma_chacha20,
    ma_hoa_rsa, giai_ma_rsa,
    tao_cap_khoa_rsa,
)

app = Flask(__name__)

THUAT_TOAN_HOP_LE = {"AES", "CHACHA20", "RSA"}

# Giới hạn dung lượng file upload để tránh người dùng gửi ảnh quá lớn làm tràn RAM
# (vì giờ xử lý hoàn toàn trong bộ nhớ, không còn ghi tạm ra đĩa để giới hạn tự nhiên nữa)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB


# ============================================================
# 0. GIAO DIỆN WEB (Flask tự render, không cần nginx/apache)
# ============================================================
@app.route("/", methods=["GET"])
def trang_chu():
    # Ép rõ charset=utf-8 trong header, tránh trường hợp trình duyệt/hệ điều hành
    # tự đoán sai encoding rồi hiển thị lỗi font tiếng Việt (vd: "xuâ´t" thay vì "xuất")
    return render_template("index.html"), 200, {"Content-Type": "text/html; charset=utf-8"}


# ============================================================
# 1. ENDPOINT: Tạo cặp khóa RSA
# ============================================================
@app.route("/api/rsa/tao-khoa", methods=["POST"])
def api_tao_khoa_rsa():
    """
    Body JSON (tùy chọn): { "do_dai_bit": 2048 }
    Trả về: { "khoa_cong_khai": "...", "khoa_rieng_tu": "..." }
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


# ============================================================
# 2. ENDPOINT: Mã hóa + Nhúng watermark vào ảnh -> trả về ảnh
# ============================================================
@app.route("/api/nhung", methods=["POST"])
def api_nhung_watermark():
    """
    Form-data (multipart/form-data):
      - anh: file ảnh gốc (bắt buộc)
      - watermark: chuỗi văn bản cần giấu (bắt buộc)
      - thuat_toan: "AES" | "CHACHA20" | "RSA" (bắt buộc)
      - khoa: mật khẩu (AES/CHACHA20) HOẶC khóa công khai PEM (RSA) (bắt buộc)

    Trả về: file ảnh PNG đã nhúng watermark (đính kèm để tải về).
    """
    try:
        # ---- Kiểm tra dữ liệu đầu vào ----
        if "anh" not in request.files:
            return jsonify({"thanh_cong": False, "loi": "Thiếu file ảnh (field 'anh')."}), 400

        file_anh = request.files["anh"]
        watermark = request.form.get("watermark")
        thuat_toan = (request.form.get("thuat_toan") or "").upper()
        khoa = request.form.get("khoa")

        if not watermark:
            return jsonify({"thanh_cong": False, "loi": "Thiếu watermark."}), 400
        if thuat_toan not in THUAT_TOAN_HOP_LE:
            return jsonify({"thanh_cong": False, "loi": f"thuat_toan phải là một trong {THUAT_TOAN_HOP_LE}"}), 400
        if not khoa:
            return jsonify({"thanh_cong": False, "loi": "Thiếu khóa (mật khẩu hoặc khóa công khai RSA)."}), 400

        # ---- Đọc ảnh vào RAM (không ghi ra đĩa) ----
        du_lieu_anh_goc = file_anh.read()  # bytes, giữ nguyên trong bộ nhớ

        # ---- Mã hóa watermark theo thuật toán đã chọn ----
        if thuat_toan == "AES":
            ban_ma = ma_hoa_aes(watermark, khoa)
        elif thuat_toan == "CHACHA20":
            ban_ma = ma_hoa_chacha20(watermark, khoa)
        else:  # RSA
            ban_ma = ma_hoa_rsa(watermark, khoa)  # khoa = khóa công khai PEM

        # ---- Kiểm tra sức chứa trước khi nhúng ----
        # (mỗi lần Image.open() cần 1 buffer BytesIO riêng, không dùng chung con trỏ đọc)
        if not kiem_tra_suc_chua(io.BytesIO(du_lieu_anh_goc), ban_ma):
            return jsonify({
                "thanh_cong": False,
                "loi": "Ảnh không đủ dung lượng để nhúng bản mã (watermark quá dài so với kích thước ảnh)."
            }), 400

        # ---- Nhúng vào ảnh, kết quả ghi thẳng vào buffer RAM ----
        buffer_dich = io.BytesIO()
        nhung_thong_diep(io.BytesIO(du_lieu_anh_goc), buffer_dich, ban_ma)
        buffer_dich.seek(0)  # đưa con trỏ đọc về đầu để send_file đọc đúng từ đầu

        return send_file(
            buffer_dich,
            mimetype="image/png",
            as_attachment=True,
            download_name="anh_da_nhung_watermark.png"
        )

    except Exception:
        return jsonify({"thanh_cong": False, "loi": traceback.format_exc()}), 500


# ============================================================
# 3. ENDPOINT: Trích xuất + Giải mã watermark từ ảnh
# ============================================================
@app.route("/api/trich-xuat", methods=["POST"])
def api_trich_xuat_watermark():
    """
    Form-data (multipart/form-data):
      - anh: file ảnh đã nhúng watermark (bắt buộc)
      - thuat_toan: "AES" | "CHACHA20" | "RSA" (bắt buộc)
      - khoa: mật khẩu (AES/CHACHA20) HOẶC khóa riêng tư PEM (RSA) (bắt buộc)

    Trả về JSON: { "thanh_cong": true, "watermark": "..." }
    """
    try:
        if "anh" not in request.files:
            return jsonify({"thanh_cong": False, "loi": "Thiếu file ảnh (field 'anh')."}), 400

        file_anh = request.files["anh"]
        thuat_toan = (request.form.get("thuat_toan") or "").upper()
        khoa = request.form.get("khoa")

        if thuat_toan not in THUAT_TOAN_HOP_LE:
            return jsonify({"thanh_cong": False, "loi": f"thuat_toan phải là một trong {THUAT_TOAN_HOP_LE}"}), 400
        if not khoa:
            return jsonify({"thanh_cong": False, "loi": "Thiếu khóa (mật khẩu hoặc khóa riêng tư RSA)."}), 400

        # ---- Đọc ảnh vào RAM, không ghi ra đĩa ----
        du_lieu_anh = file_anh.read()

        ban_ma = trich_xuat_thong_diep(io.BytesIO(du_lieu_anh))
        if ban_ma is None:
            return jsonify({"thanh_cong": False, "loi": "Không tìm thấy dữ liệu ẩn trong ảnh."}), 400

        if thuat_toan == "AES":
            watermark = giai_ma_aes(ban_ma, khoa)
        elif thuat_toan == "CHACHA20":
            watermark = giai_ma_chacha20(ban_ma, khoa)
        else:  # RSA
            watermark = giai_ma_rsa(ban_ma, khoa)  # khoa = khóa riêng tư PEM

        if watermark is None:
            return jsonify({"thanh_cong": False, "loi": "Sai khóa hoặc dữ liệu bị hỏng, không thể giải mã."}), 400

        return jsonify({"thanh_cong": True, "watermark": watermark})

    except Exception:
        return jsonify({"thanh_cong": False, "loi": traceback.format_exc()}), 500


if __name__ == "__main__":
    app.run(debug=True, port=5000)
