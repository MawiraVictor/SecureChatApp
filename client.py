import socket
import json
import time 
import struct
import select
import threading
from base64 import b64encode,b64decode

import Crypto
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad,unpad
from Crypto.Cipher import PKCS1_OAEP, AES


class Client():
    def __init__(self, on_message=None):
        self.client_socket = None
        self.server_port = 9876
        self.server_address = "localhost"

        self.username = ""
        self.password = ""
        self.private_key: RSA.RsaKey = None
        self.public_key : RSA.RsaKey =  None
        self.peers: list[Client_Peer] = []

        self.on_message = on_message #callback for GUI

        self.gen_keypair()

    def dial_server(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
            self.client_socket.settimeout(10)

            self.client_socket.connect((self.server_address, self.server_port))
            self.client_socket.setblocking(False)

            print("Connected to server")

        except socket.timeout:
            print("Connection to server timed out")
        except socket.gaierror:
            print("DNS related error")
        except ConnectionRefusedError:
            print("Connection Refused by server")
        except OSError as e:
            print(f"Got error: {e}")
        except Exception as e:
            print(f"Got error: {e}")

    def poll_server(self):
        sockets2poll = [self.client_socket]
        buffers = {self.client_socket: b''}
        try:
            readable, _, _ = select.select(sockets2poll, [], [], 0)
            for sock in readable:
                if sock == self.client_socket:
                    data = sock.recv(4096)
                    if not data:
                        print("Server closed Connection")
                        return
                    
                    buffers[sock] += data
                    self.process_buffer(sock,buffers)
        except KeyboardInterrupt:
            print("Stopping Client")
            self.client_socket.close()

    def process_buffer(self, sock, buffers):
        buf = buffers[sock]
        while True:
            if len(buf) < 4:
                break       #not enough to read header
            msg_len = struct.unpack(">I", buf[:4])[0]
            
            if len(buf) < 4 + msg_len:
                break #full message not yet received

            msg_data = buf[4: 4+msg_len]
            buf = buf[4+msg_len:]
            self.process_message(msg_data)
        buffers[sock] = buf

    def process_message(self, msg_bytes) -> int:
        msg = json.loads(msg_bytes.decode("utf-8"))
        print(f"Received message: {msg}")
        #read the command from dictionary
        command = msg["command"]
        #availabe commands from server: auth_granted,auth_denied,new_peer,close_peer,recv_message

        match command:
            case "auth_denied" | "auth_granted":
                self.handle_auth_response(command, msg)
            case "recv_message":
                self.receive_message(msg)
            case "recv_session_key":
                self.receive_session_key(msg)
            case "new_peer":
                self.handle_new_peer(msg)
            case "close_peer":
                self.remove_peer(msg)
            case _:
                print(f"Got unknown command: {command}")


    def gen_keypair(self):
        self.private_key = RSA.generate(3072)
        self.public_key = self.private_key.public_key()

    def gen_sessionkey(self, peer: Client_Peer) -> bytes:
        #32 byte session key for AES-256
        session_key = Crypto.Random.get_random_bytes(32)

        #converting session key in base64
        session_key_b64 = b64encode(session_key).decode("utf-8")

        #store the session key as string in base64
        peer.session_key = session_key_b64

        #encrypting session key using RSA public key cryptography
        cipher_rsa = PKCS1_OAEP.new(peer.public_key)
        encrypted_session_key = cipher_rsa.encrypt(session_key)

        return encrypted_session_key

    def send_encrypted_message(self, peer_username, message):
        #convert message to bytes
        message = message.encode("utf-8")

        #first look up session key
        session_key = None
        for peer in self.peers:
            if peer.name == peer_username:
                session_key = peer.session_key
                if not session_key:
                    # if no session key yet first generate and send it
                    self.send_session_key(peer)
                    # wait for five seconds
                    time.sleep(5)
                    session_key = peer.session_key
                break 

        if session_key is None:
            print(f"No peer: {peer_username}")
            return 

        #encrypting message using session_key
        cipher_aes = AES.new(session_key, AES.MODE_CBC)

        encrypted_message_bytes = cipher_aes.encrypt(pad(message, AES.block_size)) 

        #convert iv and cipher text to base64 for proper transmission
        iv = b64encode(cipher_aes.iv).decode("utf-8")
        encrypted_message = b64encode(encrypted_message_bytes).decode("utf-8")

        data = {
            "command": "send_message",
            "username": self.username,
            "peername": peer_username,
            "message": encrypted_message,
            "iv":      iv,
        }

        self.send_to_server(data)
        
    def send_session_key(self, peer: Client_Peer):
        #get peer public key    
        peer_pub_key = None
        
        peer_username = peer.name
        peer_pub_key = peer.public_key

        if peer_pub_key is None:
            print(f"Don't have public key for {peer_username}")
            return

        enc_session_key = self.gen_sessionkey(peer)

        #converting session key in base64
        session_key = b64encode(enc_session_key).decode("utf-8")

        data = {
            "command": "exchange_session_key",
            "username": self.username,
            "peername": peer_username,
            "session_key": session_key
        }

        self.send_to_server(data)



    def send_login_request(self):
        #export key as PEM
        public_key_pem = self.public_key.export_key().decode("utf-8")

        data = {
            "command": "login",
            "username": self.username,
            "password": self.password,
            "public_key": public_key_pem
        }

        self.send_to_server(data)

    def send_signup_request(self):
        #export key as PEM
        public_key_pem = self.public_key.export_key().decode("utf-8")

        data = {
            "command": "signup",
            "username": self.username,
            "password": self.password,
            "public_key": public_key_pem
        }

        self.send_to_server(data)

    def handle_auth_response(self, command, data: dict):
        if command == "auth_denied":
            return False
        
        #getting peers if any
        for peer in data["peers"]:
            peer_pub_key = peer["public_key"]
            #extract pub key from pem format
            peer_pub_key = RSA.import_key(peer_pub_key.encode("utf-8"))
            self.peers.append(Client_Peer(peer["username"], peer_pub_key))


        self.send_to_gui("show_chat", None)
        return True

    def handle_new_peer(self, data: dict):
        peer_pub_key = data["public_key"]

        #extract pub key from pem format
        peer_pub_key = RSA.import_key(peer_pub_key.encode("utf-8"))

        self.peers.append(Client_Peer(data["peername"], peer_pub_key))

    def remove_peer(self, data:dict):
        name = data["peername"]

        for peer in self.peers:
            if peer.name == name:
                self.peers.remove(peer)
                print(f"Peer: {name} is removed")
                break

    def receive_message(self, data:dict):
        iv = data["iv"]
        message = data["message"]
        peer_name = data["peername"]

        #convert from base64 which return bytes
        encrypted_message = b64decode(message)
        iv = b64decode(iv)

        #find peer_name's sesssion_key
        session_key = None
        for peer in self.peers:
            if peer.name == peer_name:
                session_key = peer.session_key
                break

        #if no session_key found
        if not session_key:
            print(f"Could not get session_key for {peer_name}")
            return

        #decrypting data using session_key
        cipher_aes = AES.new(key=session_key, mode=AES.MODE_CBC, iv=iv)

        padded_decrypted_message = cipher_aes.decrypt(encrypted_message)
        #remove padding added
        decrypted_message = unpad(padded_decrypted_message, AES.block_size)

        print(f"Message from {peer_name}: {decrypted_message}")

    def receive_session_key(self, data:dict) -> bool:
        peer_name = data["peername"]
        session_key = data["session_key"]

        for peer in self.peers:
            if peer.name == peer_name:
                #Decrypt session_key with private_key
                cipher_rsa = PKCS1_OAEP.new(self.private_key)

                session_key = b64decode(session_key)

                decrypted_session_key = cipher_rsa.decrypt(session_key)
    
                peer.session_key = b64encode(decrypted_session_key).decode("utf-8")
                
                print(f"Session key for {peer_name} successfully added")
                #indicate sucess
                return True

        return False

    def send_to_server(self, data: dict):
        #convert dictionary to json
        data = json.dumps(data).encode("utf-8")
        
        #prepare the length of data to be sent with the data itself
        data_len = struct.pack(">I", len(data)) #">I" for unsigned int in big endian

        #send the lenght first then the data appended to lenght
        self.client_socket.sendall(data_len + data)

    def send_to_gui(self, msg, data=None):
        if self.on_message:
            self.on_message(msg, data)

class Client_Peer():
    def __init__(self, peer_name: str, public_key: RSA.RsaKey):
        self.name = peer_name
        self.public_key: RSA.RsaKey = public_key
        self.session_key:str = None #in base 64

    def get_publickey(self):
        return self.public_key

    def set_publickey(self, public_key):
        self.public_key = public_key


if __name__ == "__main__":
    client = Client()
    client.username = "tom"
    client.password = "kaps"

    client.dial_server()
    
    try:
        i = 0
        sent_signup = False
        sent_message = False

        while True:
            client.poll_server()

            if not sent_signup:
                client.send_signup_request()
                sent_signup = True

            
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nClient Stopped..")

