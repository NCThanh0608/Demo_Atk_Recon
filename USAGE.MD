# USAGE.MD — Hướng dẫn truy cập & sử dụng

Hướng dẫn vận hành nhanh Red Team Ops Console cho demo (engagement `VQEC-RT-01`).

## 1. Thông tin kết nối

| Mục | Giá trị |
|---|---|
| Wi-Fi (SSID) | `Hacker` |
| Mật khẩu Wi-Fi | `1234567890` |
| IP Raspberry Pi (AP) | `10.42.0.1` |
| Địa chỉ web console | `http://10.42.0.1:8080` |
| SSH | `ssh pi@10.42.0.1` (mật khẩu: `1`) |

> ⚠️ Đây là thông tin **mạng lab nội bộ** cho mục đích demo được ủy quyền. Ai có quyền đọc repo
> đều thấy mật khẩu này — chỉ dùng cho lab, không tái sử dụng cho mạng thật.

## 2. Các bước truy cập

1. Trên laptop/điện thoại, nối Wi-Fi **`Hacker`** (mật khẩu `1234567890`).
2. Mở trình duyệt tới **http://10.42.0.1:8080**.
3. Góc phải hiển thị trạng thái backend:
   - **Backend trực tuyến** → điều khiển thật.
   - **Mock (chưa có backend)** → chạy dữ liệu giả lập để demo giao diện.

## 3. Sử dụng console

1. Nhập **Dải IP quét** (vd `192.168.1.0/24`) và **IP mục tiêu** (vd `192.168.1.30`).
2. Bật/tắt từng chức năng bằng công tắc:
   - **Scan IP** — phát hiện host sống trong dải.
   - **Scan Port** — liệt kê cổng mở của mục tiêu.
   - **Brute Force** — dò thông tin đăng nhập.
   - **DoS** — tấn công thể tích (chỉ bật khi IP mục tiêu thuộc mạng nội bộ RFC1918).
3. Theo dõi kết quả real-time ở khung **Nhật ký hoạt động**.

> Công tắc **DoS** tự khóa nếu IP mục tiêu là địa chỉ công cộng.

## 4. Quản lý web server trên Pi

**Nếu đã cài systemd service** (xem `deploy/`):
```bash
ssh pi@10.42.0.1 'sudo systemctl status redteam-console'    # trạng thái
ssh pi@10.42.0.1 'sudo systemctl restart redteam-console'   # khởi động lại
ssh pi@10.42.0.1 'journalctl -u redteam-console -e'         # xem log
```

**Nếu chạy tạm (nohup):**
```bash
# chạy:
ssh pi@10.42.0.1 'cd ~/demo_atk_recon/frontend && nohup python3 -m http.server 8080 --bind 0.0.0.0 >~/demo_atk_recon/server.log 2>&1 </dev/null &'
# dừng:
ssh pi@10.42.0.1 'pkill -f "http.server 8080"'
```

## 5. Xử lý sự cố

| Triệu chứng | Kiểm tra |
|---|---|
| Không mở được web | Đã nối đúng Wi-Fi `Hacker` chưa? `ping 10.42.0.1` |
| Web mở nhưng báo "Mock" | Backend chưa chạy → bình thường khi chưa có backend |
| Công tắc DoS bị mờ/khóa | IP mục tiêu phải thuộc `10/8`, `172.16/12`, `192.168/16` |
| Server không tự chạy sau reboot | Chưa cài systemd service → chạy `deploy/install-service.sh` trên Pi |
