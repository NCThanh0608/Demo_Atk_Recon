#!/usr/bin/env python3
"""
pi_uart_server.py — chạy trên Raspberry Pi.
Lắng nghe lệnh từ UART (GPIO14/15), thực thi, trả kết quả về.

Kết nối phần cứng:
  Pi GPIO14 (Pin 8,  TX) → RX của USB-TTL adapter trên laptop
  Pi GPIO15 (Pin 10, RX) → TX của USB-TTL adapter trên laptop
  Pi GND    (Pin 6)      → GND của adapter

Chạy: python3 pi_uart_server.py
"""

import serial
import subprocess
import sys
import os

DEVICE   = "/dev/serial0"   # GPIO UART trên Pi
BAUDRATE = 115200
PROMPT   = b"pi> "

def run_cmd(cmd: str) -> str:
    if not cmd.strip():
        return ""
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=15,
            cwd="/home/pi"
        )
        out = (r.stdout + r.stderr).strip()
        return out if out else "(không có output)"
    except subprocess.TimeoutExpired:
        return "[timeout]"
    except Exception as e:
        return f"[lỗi: {e}]"

def main():
    print(f"[uart-server] mở {DEVICE} @ {BAUDRATE}", flush=True)
    try:
        ser = serial.Serial(DEVICE, BAUDRATE, timeout=1)
    except serial.SerialException as e:
        print(f"[uart-server] KHÔNG MỞ ĐƯỢC {DEVICE}: {e}", file=sys.stderr)
        sys.exit(1)

    ser.write(b"\r\n=== Pi UART Server ===\r\n")
    ser.write(PROMPT)
    buf = b""

    print("[uart-server] sẵn sàng nhận lệnh", flush=True)
    while True:
        try:
            data = ser.read(64)
        except serial.SerialException:
            break
        if not data:
            continue

        # echo lại ký tự gõ
        ser.write(data)

        buf += data
        while b"\r" in buf or b"\n" in buf:
            idx = -1
            for sep in (b"\r\n", b"\r", b"\n"):
                i = buf.find(sep)
                if i != -1 and (idx == -1 or i < idx):
                    idx = i
                    found_sep = sep
            if idx == -1:
                break
            line = buf[:idx].decode(errors="replace").strip()
            buf  = buf[idx + len(found_sep):]

            if line.lower() in ("exit", "quit"):
                ser.write(b"\r\n[server] tạm biệt\r\n")
                ser.close()
                return

            result = run_cmd(line)
            ser.write(b"\r\n" + result.encode(errors="replace") + b"\r\n")
            ser.write(PROMPT)

if __name__ == "__main__":
    main()
