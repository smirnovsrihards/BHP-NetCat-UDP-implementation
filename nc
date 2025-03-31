#!/usr/bin/env python3

import socket
import threading
import sys 
import textwrap
import argparse
import shlex
import subprocess

def execute(cmd):
    cmd = cmd.strip()
    if not cmd:
        return
    output = subprocess.check_output(shlex.split(cmd), stderr=subprocess.STDOUT)
    return output.decode()

class NetCat:
    def __init__(self, args, buffer=None):
        self.args = args
        self.buffer = buffer
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    def run(self):
        if self.args.listen:
            self.listen()
        else:
            self.send()
            
    def send(self):
        self.socket.connect((self.args.target, self.args.port))
        if self.buffer:
            self.socket.send(self.buffer)
        
        try:
            while True:
                recv_len = 1
                response = ''
                while recv_len:
                    data = self.socket.recv(4096)
                    recv_len = len(data)
                    response += data.decode()
                    if recv_len < 4096:
                        break
                if response:
                    print(response)
                    buffer = input('>_ ')
                    buffer += '\n'
                    self.socket.send(buffer.encode())
        except KeyboardInterrupt:
            print('User terminated.')
            self.socket.close()
            sys.exit()
    
    def listen(self):
        self.socket.bind((self.args.target, self.args.port))
        self.socket.listen(5)
        while True:
             client_socket, _ = self.socket.accept()
             client_thread = threading.Thread(target=self.handle, args=(client_socket,))
             client_thread.start()

    def handle(self, client_socket):
        if self.args.execute:
            output = execute(self.args.execute)
            client_socket.send(output.encode())
        elif self.args.upload:
            file_buffer = b''
            while True:
                data = client_socket.recv(4096)
                if data: 
                    file_buffer += data
                else:
                    break
            with open(self.args.upload, 'wb') as f:
                f.write(file_buffer)
            message = f'Saved file {self.args.upload}'
            client_socket.send(message.encode())

        elif self.args.command:
            cmd_buffer = b'' # Initialize as bytes
            while True:
                try:
                    client_socket.send(b'BHP: #> ')
                    while b'\n' not in cmd_buffer:
                        # Receive data and decode immediately
                        cmd_buffer += client_socket.recv(64)
                    # Execute the command, strip any extra whitespace
                    response = execute(cmd_buffer.decode().strip())
                    if response:
                        client_socket.send(response.encode())
                    # Clear the buffer for the next command
                    cmd_buffer = b''
                except Exception as e:
                    print(f'Server killed {e}')
                    self.socket.close() # Close client socket
                    break

class NetCat_UDP:
    def __init__(self, args, buffer=None):
        self.args = args
        self.buffer = buffer
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
           
    def run(self):
        if self.args.listen:
            self.listen()
        else:
             self.send()
               
    def send(self):
        self.socket.sendto(self.buffer, (self.args.target, self.args.port))
        try:
            while True:
                recv_len = 1
                response = ''
                while recv_len:
                    data, addr = self.socket.recvfrom(4096) #Receive data
                    recv_len = len(data)
                    response += data.decode()
                    if recv_len < 4096:
                        break
                if response:
                    print(response)
                    buffer = input('>_ ')
                    buffer += '\n'
                    self.socket.sendto(buffer.encode(), (self.args.target, self.args.port))
        except KeyboardInterrupt:
            print("User Terminated.")
            self.socket.close()
            sys.exit() 

    def listen(self):
        self.socket.bind((self.args.target, self.args.port))
        print(f"Socket bind to {self.args.target}:{self.args.port}")
        while True:
            data, client_address = self.socket.recvfrom(4096)
            print(f'Received: {data.decode()} from {client_address}')
            #Directly handle data or spawn a thread
            client_thread = threading.Thread(target=self.handle, args=(data, client_address))
            client_thread.start()

    def handle(self, data, client_address):
        if self.args.execute:
            output = execute(self.args.execute)
            self.socket.sendto(output.encode(), client_address)
        elif self.args.upload:
            with open(self.args.upload, 'wb') as f:
                f.write(data)
            message = f'Saved file {self.args.upload}'
            self.socket.sendto(message.encode(), client_address)
        elif self.args.command:
            cmd_buffer = b'' # Buffer to accumulate incoming command data
            while True:
                try:
                    # Send initial prompt to the client
                    self.socket.sendto(b'BHP: #> ', client_address)
                    # Wait response from client
                    data, client_address = self.socket.recvfrom(4096)
                    cmd_buffer += data # Accumulate command data
                    if b'\n' in cmd_buffer:
                        response = execute(data.decode().strip())
                        if response:
                            self.socket.sendto(response.encode(), client_address)
                        cmd_buffer = b''
                except Exception as e:
                    print(f'Server killed {e}')
                    self.socket.close()
                    break
                    
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='BHP Net Tool', 
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''Example:
            ./nc -t 192.168.88.1 -p 5555 -l -c
            ./nc -t 192.168.88.1 -p 5555 -l -u=mytest.txt 
            ./nc -t 192.168.88.1 -p 5555 -l -e=\"cat /etc/passwd\" 
            echo 'ABC' | ./netcat.py -t 192.168.88.1 -p 135             
            ./nc -t 192.168.88.1 -p 5555 
            ./nc -t 192.168.88.1 -p 1234 --udp
            '''))
    parser.add_argument('-c', '--command', action='store_true', help='command shell')
    parser.add_argument('-e', '--execute', help='execute specified command')
    parser.add_argument('-l', '--listen', action='store_true', help='listen')
    parser.add_argument('-p', '--port', type=int, default=5555, help='specified port')
    parser.add_argument('-t', '--target', default='192.168.88.1', help='specified IP')
    parser.add_argument('-u', '--upload', help='upload file')
    parser.add_argument('--udp', action='store_true',  help='establish udp connection')
    args = parser.parse_args()

    if args.listen:
        buffer = ''
    else:
        buffer = sys.stdin.read()

    if args.udp:
        nc = NetCat_UDP(args, buffer.encode())
        nc.run()
    else:
        nc = NetCat(args, buffer.encode())
        nc.run()
