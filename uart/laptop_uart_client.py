#!/usr/bin/env python3
"""
laptop_uart_client.py — chạy trên laptop.
Terminal tương tác qua USB-TTL adapter kết nối với Pi GPIO UART.

Yêu cầu: pip install pyserial

Dùng:
  python3 laptop_uart_client.py                  # tự dò /dev/ttyUSB0
  python3 laptop_uart_client.py /dev/ttyUSB1     # chỉ định cổng
  python3 laptop_uart_client.py COM3             # Windows
"""

import serial
import sys
import threading
import time

BAUDRATE = 115200

def find_port():
    import glob
    candidates = glob.glob("/dev/ttyUSB*") + glob.glob("/dev/ttyACM*") + glob.glob("/dev/tty.usbserial*")
    if candidates:
        return candidates[0]
    return None

def recv_loop(ser):
    while True:
        try:
            data = ser.read(256)
        except serial.SerialException:
            print("\n[client] mất kết nối")
            break
        if data:
            sys.stdout.write(data.decode(errors="replace"))
            sys.stdout.flush()

def main():
    port = sys.argv[1] if len(sys.argv) > 1 else find_port()
    if not port:
        print("[client] không tìm thấy cổng serial. Cắm adapter USB-TTL vào laptop.")
        sys.exit(1)

    print(f"[client] kết nối {port} @ {BAUDRATE} baud")
    print("[client] gõ lệnh shell → Enter để gửi. Ctrl+C để thoát.\n")

    try:
        ser = serial.Serial(port, BAUDRATE, timeout=0.1)
    except serial.SerialException as e:
        print(f"[client] lỗi mở {port}: {e}")
        sys.exit(1)

    # Luồng nhận chạy nền
    t = threading.Thread(target=recv_loop, args=(ser,), daemon=True)
    t.start()

    try:
        while True:
            line = input()          # block cho đến khi người dùng gõ Enter
            ser.write((line + "\r\n").encode())
    except (KeyboardInterrupt, EOFError):
        print("\n[client] đóng")
        ser.close()

if __name__ == "__main__":
    main()
