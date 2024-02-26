#!/usr/bin/python3

import socket
import threading
import os
import queue
import time

HOST = "127.0.0.1"
PORT = 22222


HS1_C2S_MESSAGE = b"ssh_lite v1.0 - c2s"
HS1_S2C_MESSAGE = b"ssh_lite v1.0 - s2c"
HS2_C2S_MESSAGE = b"exchange keys - c2s"
HS2_S2C_MESSAGE = b"exchange keys - s2c"
KEY_EXCHANGE = 1
TEST_CRYPTO = 2
ENCRYPTED_MSG = 3


class Server:
    def __init__(self):
        self.rx_fifo = queue.Queue()
        self.tx_fifo = queue.Queue()
        self.key = self.read_key_from_file("sshd_lite")
        self.pub = self.read_key_from_file("sshd_lite.pub")

    def generate_iv(length):
        return os.urandom(length)

    def xor_bytes(self, byte_array1, byte_array2):
        return bytes(byte1 ^ byte2 for byte1, byte2 in
                     zip(byte_array1, byte_array2))

    def decrypt_byte_array(self, encrypted_data):
        iv = encrypted_data[:len(encrypted_data) // 2]
        encrypted_data = encrypted_data[len(encrypted_data) // 2:]
        decrypted_data = self.xor_bytes(encrypted_data, iv)
        decrypted_data = self.xor_bytes(decrypted_data, self.key)

        return decrypted_data

    def encrypt_byte_array(self, byte_array):
        iv = os.urandom(len(byte_array))
        encrypted_data = self.xor_bytes(byte_array, self.key)
        encrypted_data = self.xor_bytes(encrypted_data, iv)
        return iv + encrypted_data

    def read_key_from_file(self, key_file):
        with open(key_file, 'rb') as f:
            key = f.read().strip()
        return key

    def parse_data(self, data):
        sequence = data[0]
        cmd = data[1]
        payload = data[2:]
        return (sequence, cmd, payload)

    def server_tx_fifo_put(self, msg):
        self.tx_fifo.put(msg)

    def start_server(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((HOST, PORT))
        self.server_socket.listen()
        print(f"Server listening on {HOST}:{PORT}")

        while True:
            conn, addr = self.server_socket.accept()
            threading.Thread(
                target=self.server_recv_thread, args=(conn, addr)).start()
            threading.Thread(
                target=self.server_rx_fifo_get_thread, args=()).start()
            threading.Thread(
                target=self.server_send_thread, args=(conn, addr)).start()

    def server_recv_thread(self, conn, addr):
        while True:
            data = conn.recv(1024)
            if not data:
                break
            self.rx_fifo.put(data)

    def server_rx_fifo_get_thread(self):
        while True:
            data = self.rx_fifo.get()
            seq, cmd, payload = self.parse_data(data)
            print(f'server || data in :: {data}')
            print(f'          seq :: {seq}')
            print(f'          cmd :: {cmd}')
            print(f'          payload :: {payload}')

            if payload == HS1_C2S_MESSAGE:
                msg = bytearray(HS1_S2C_MESSAGE)
                seq = seq.to_bytes(1, 'big')
                cmd = cmd | 0x80
                cmd = cmd.to_bytes(1, 'big')
                msg = (seq + cmd + msg)
                self.server_tx_fifo_put(msg)
            if cmd == KEY_EXCHANGE:
                msg = bytearray(self.pub)
                seq = seq.to_bytes(1, 'big')
                cmd = cmd | 0x80
                cmd = cmd.to_bytes(1, 'big')
                msg = (seq + cmd + msg)
                self.server_tx_fifo_put(msg)
            if cmd == TEST_CRYPTO:
                msg = bytearray(self.decrypt_byte_array(payload))
                seq = seq.to_bytes(1, 'big')
                cmd = cmd | 0x80
                cmd = cmd.to_bytes(1, 'big')
                msg = (seq + cmd + msg)
                self.server_tx_fifo_put(msg)

    def server_send_thread(self, conn, addr):
        while True:
            data = self.tx_fifo.get()
            print(f'server || data out :: {data}')
            conn.sendall(data)


class Client:
    def __init__(self):
        self.state = 'handshake'
        self.fifo = queue.Queue()
        self.key = self.read_key_from_file("sshd_lite")
        self.pub = self.read_key_from_file("sshd_lite.pub")
        self.sequence = 0

    def generate_iv(length):
        return os.urandom(length)

    def xor_bytes(self, byte_array1, byte_array2):
        return bytes(byte1 ^ byte2 for byte1, byte2 in
                     zip(byte_array1, byte_array2))

    def decrypt_byte_array(self, encrypted_data):
        iv = encrypted_data[:len(encrypted_data) // 2]
        encrypted_data = encrypted_data[len(encrypted_data) // 2:]
        decrypted_data = self.xor_bytes(encrypted_data, iv)
        decrypted_data = self.xor_bytes(decrypted_data, self.key)

        return decrypted_data

    def encrypt_byte_array(self, byte_array):
        iv = os.urandom(len(byte_array))
        encrypted_data = self.xor_bytes(byte_array, self.key)
        encrypted_data = self.xor_bytes(encrypted_data, iv)
        return iv + encrypted_data

    def read_key_from_file(self, key_file):
        with open(key_file, 'rb') as f:
            key = f.read().strip()
        return key

    def parse_data(self, data):
        sequence = data[0]
        cmd = data[1]
        payload = data[2:]
        return (sequence, cmd, payload)

    def client_recv_thread():
        while True:
            data = self.client_socket.recv(1024)
            if not data:
                break
            self.fifo.put(data)

    def client_send_thread():
        pass

    def client_thread(self):
        if self.state == 'handshake':
            msg = bytearray(HS1_C2S_MESSAGE)
            seq = self.sequence.to_bytes(1, 'big')
            cmd = 0x00
            cmd = cmd.to_bytes(1, 'big')
            msg = (seq + cmd + msg)
            print(f'client || data out :: {msg}')
            self.client_socket.sendall(msg)

            data = self.client_socket.recv(1024)
            seq, cmd, payload = self.parse_data(data)
            print(f'client || data in :: {data}')
            print(f'          seq :: {seq}')
            print(f'          cmd :: {cmd}')
            print(f'          payload :: {payload}')

            if payload == HS1_S2C_MESSAGE:
                self.state = 'exchange_key'
                print("client: handshake > exchange_key")
                self.sequence += 1

        if self.state == 'exchange_key':
            seq = (self.sequence.to_bytes(1, 'big'))
            cmd = KEY_EXCHANGE.to_bytes(1, 'big')
            payload = self.pub
            msg = (seq + cmd + payload)
            print(f'client || data out :: {msg}')
            self.client_socket.sendall(msg)
            data = self.client_socket.recv(1024)
            seq, cmd, payload = self.parse_data(data)
            print(f'client || data in :: {data}')
            print(f'          seq :: {seq}')
            print(f'          cmd :: {cmd}')
            print(f'          payload :: {payload}')
            self.state = 'test_encryption'
            self.server_pub = payload
            print(f'client || pub :: {self.server_pub}')
            print("client: exchange_key > test_encryption")
            self.sequence += 1

        if self.state == 'test_encryption':
            seq = (self.sequence.to_bytes(1, 'big'))
            cmd = TEST_CRYPTO .to_bytes(1, 'big')
            payload = self.encrypt_byte_array(b'hello')
            msg = (seq + cmd + payload)
            print(f'client || data out :: {msg}')
            self.client_socket.sendall(msg)
            data = self.client_socket.recv(1024)
            seq, cmd, payload = self.parse_data(data)
            print(f'client || data in :: {data}')
            print(f'          seq :: {seq}')
            print(f'          cmd :: {cmd}')
            print(f'          payload :: {payload}')
            if payload == b'hello':
                print("good key exchange and encryption")

    def start_connection(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((HOST, PORT))

        threading.Thread(
            target=self.client_thread, args=()).start()


def run_thread_1():
    server = Server()
    server.start_server()


def run_thread_2():
    client = Client()
    client.start_connection()


def main():
    thread_1 = threading.Thread(
        target=run_thread_1, args=())
    thread_2 = threading.Thread(
        target=run_thread_2, args=())

    thread_1.start()
    time.sleep(1)
    thread_2.start()

    thread_1.join()
    thread_2.join()


if __name__ == "__main__":
    main()
