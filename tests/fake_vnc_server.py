#!/usr/bin/env python3
import argparse
import socket
import struct
import time


def serve_once(port, mode, v33):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(1)
        print("READY", flush=True)
        conn, _ = srv.accept()
        with conn:
            conn.settimeout(2.0)
            if v33:
                conn.sendall(b"RFB 003.003\n")
            else:
                conn.sendall(b"RFB 003.008\n")
            try:
                conn.recv(12)
            except socket.timeout:
                pass

            if mode in ("frame", "frame-auth"):
                conn.sendall(b"\x01\x01")
                try:
                    conn.recv(1)
                except socket.timeout:
                    return
                if mode == "frame-auth":
                    conn.sendall(b"\x01\x02")
                    try:
                        conn.recv(1)
                    except socket.timeout:
                        return
                    conn.sendall(b"\x00" * 16)
                    try:
                        conn.recv(16)
                    except socket.timeout:
                        return
                conn.sendall(struct.pack("!I", 0))
                try:
                    conn.recv(1)
                except socket.timeout:
                    return
                width = 1
                height = 1
                server_pf = struct.pack(
                    "!BBBBHHHBBB3s",
                    32,
                    24,
                    0,
                    1,
                    255,
                    255,
                    255,
                    16,
                    8,
                    0,
                    b"\x00\x00\x00",
                )
                conn.sendall(struct.pack("!HH", width, height) + server_pf + struct.pack("!I", 0))
                try:
                    conn.recv(20)
                    conn.recv(8)
                    conn.recv(10)
                except socket.timeout:
                    return
                conn.sendall(b"\x00\x00" + struct.pack("!H", 1))
                rect_hdr = struct.pack("!HHHHI", 0, 0, 1, 1, 0)
                conn.sendall(rect_hdr)
                conn.sendall(b"\x00\x00\xff\x00")
                time.sleep(0.2)
                return

            if v33:
                if mode == "noauth":
                    conn.sendall(struct.pack("!I", 1))
                elif mode == "auth":
                    conn.sendall(struct.pack("!I", 2))
                else:
                    conn.sendall(struct.pack("!I", 0))
                time.sleep(0.2)
                return

            if mode == "noauth":
                conn.sendall(b"\x01\x01")
            elif mode == "auth":
                conn.sendall(b"\x01\x02")
            else:
                conn.sendall(b"\x00" + struct.pack("!I", 5) + b"error")
            try:
                conn.settimeout(0.2)
                conn.recv(16)
            except socket.timeout:
                pass
            time.sleep(0.2)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--mode", choices=["noauth", "auth", "fail", "frame", "frame-auth"], required=True)
    parser.add_argument("--v33", action="store_true")
    args = parser.parse_args()
    serve_once(args.port, args.mode, args.v33)


if __name__ == "__main__":
    main()
