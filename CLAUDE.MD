# CLAUDE.md

Hướng dẫn cho Claude Code (và lập trình viên) khi làm việc trong repo này.

## Dự án là gì

**Demo_Atk_Recon** — công cụ demo kiểm thử tấn công/trinh sát chạy **local trên Raspberry Pi
ở chế độ Wi-Fi AP**. Operator nối vào SSID của Pi, mở web console, điều khiển 4 chức năng
bằng công tắc on/off:

1. **Scan IP** — phát hiện host sống trong một dải mạng.
2. **Scan Port** — liệt kê cổng mở của một mục tiêu.
3. **Brute Force** — dò thông tin đăng nhập dịch vụ.
4. **DoS** — tấn công thể tích vào mục tiêu (camera/router trong lab).

Mục đích: trình diễn kịch bản tấn công thực tế trong **mạng lab được ủy quyền** cho mục đích
đào tạo/đánh giá an ninh (engagement `VQEC-RT-01`).

## Phạm vi & an toàn (đọc trước khi code)

- Chỉ dùng trong **mạng lab nội bộ, được ủy quyền**. Không nhắm mục tiêu công cộng/bên thứ ba.
- Các module tấn công (`brute`, `dos`) **bắt buộc** bị ràng buộc phạm vi **RFC1918** ở backend
  (`10/8`, `172.16/12`, `192.168/16`). Guard ở frontend chỉ là UX, không phải lớp bảo vệ.
- Không mở rộng DoS ra IP công cộng, không gỡ kiểm tra scope server-side, không thêm tính năng
  che giấu/evasion. Mọi phiên phải ghi log đối soát.

## Cấu trúc repo

```
Demo_Atk_Recon/
├── frontend/                 # Web console (tĩnh, phục vụ từ Pi) — ĐÃ CÓ
│   ├── index.html
│   └── assets/
│       ├── css/styles.css
│       └── js/
│           ├── config.js     # hằng số, catalog 4 module, luật scope RFC1918
│           ├── api.js        # transport: LiveClient (REST+WS) / MockClient
│           ├── ui.js         # render DOM thuần, không network
│           └── app.js        # entry point, nối UI ⇄ api
├── backend/                  # Engine + API trên Pi — ĐỒNG NGHIỆP ĐANG LÀM
├── WEB.MD                    # HỢP ĐỒNG API: bản tin điều khiển Frontend ⇄ Pi
├── CLAUDE.md
└── .gitignore
```

## Hợp đồng API — bất biến

`WEB.MD` là nguồn sự thật cho giao tiếp frontend ⇄ backend. **Không đổi** tên endpoint,
tên field, định danh module (`scan_ip`, `scan_port`, `brute`, `dos`) hay khuôn bản tin
mà chưa cập nhật `WEB.MD` và báo cho cả hai phía. Điểm neo:

- REST điều khiển: `POST /api/ops/{module}/start|stop`, `GET /api/health`, `GET /api/status`.
- Telemetry: WebSocket `/api/stream`, bản tin `type ∈ {log, result, status}`.
- JSON `snake_case`, same-origin (`/api`), không CORS, không hard-code IP AP.

## Chạy frontend (dev)

Vì dùng ES modules, phải phục vụ qua HTTP (không mở trực tiếp `file://`):

```bash
cd frontend
python -m http.server 8000
# mở http://localhost:8000
```

Chưa có backend → frontend tự chạy **MOCK mode** (dữ liệu giả lập), chip góc phải báo
`Mock (chưa có backend)`. Khi `/api/health` trả 200, tự chuyển **live**, không cần sửa frontend.

## Backend (dành cho người làm backend)

- Phần cứng: **Raspberry Pi**, Wi-Fi **AP mode** (vd `hostapd` + `dnsmasq`, IP AP `192.168.50.1`).
- Phục vụ `frontend/` tĩnh tại `/`, cài API `/api/*` theo `WEB.MD §8 Checklist`.
- Gợi ý stack: Python (FastAPI/Flask + websockets). Engine chạy từng module như job quản lý được
  (start/stop/kill theo `job_id`), đẩy sự kiện lên `/api/stream`.
- Scope allowlist nên để file cấu hình riêng (vd `backend/scope.yaml`).

## Quy ước

- Định danh module thống nhất `snake_case` ở cả frontend, backend, log.
- Frontend: không thêm framework nặng; giữ vanilla ES modules, tách bạch `config/api/ui/app`.
- Logic nghiệp vụ không nằm trong `ui.js` (chỉ DOM); không gọi mạng ngoài `api.js`.
- Ghi log sự kiện dạng **NDJSON** (1 JSON/dòng) tại `logs/session.ndjson`.

## Trạng thái hiện tại

- [x] Frontend 4 công tắc on/off + 2 ô nhập (dải quét, IP mục tiêu) + console telemetry.
- [x] Mock mode để demo khi chưa có backend.
- [x] `WEB.MD` đặc tả bản tin điều khiển.
- [ ] Backend trên Pi (đang làm) — theo `WEB.MD §8`.
- [ ] Nối live (health → live tự động).
