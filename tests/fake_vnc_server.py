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
    parser.add_argument("--mode", choices=["noauth", "auth", "fail"], required=True)
    parser.add_argument("--v33", action="store_true")
    args = parser.parse_args()
    serve_once(args.port, args.mode, args.v33)


if __name__ == "__main__":
    main()
