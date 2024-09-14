import socket
import requests
import threading
import sys
import base64
import time
from flask import Flask, request, jsonify, make_response
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

#some constants
SERVER_PORT = 5000
BUFFER_SIZE = 4096

#method to connect to the server, runs automatically on start
def connect(key, name, port):
    key_bytes = key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    body = {"name": name, "port": port, "public_key": key_bytes} #name, listening socket port and public key; this is everything the server needs to manage each client
    while True:
        response = requests.post(("http://127.0.0.1:" + str(SERVER_PORT) + "/connect"), data=body)

        if response.status_code == 200:
            print(response.text, "\n") #successful connection
            return
        else:
            print("Failed to connect. error:\n", str(response.text), "\n\n")
            time.sleep(5) #if we fail to connect, we wait 5 seconds before trying to connect again

#this method gets called by the send messages method
def request_keys(port):
    body = {"origin": port} #included in the request so the server can easily check if we should be allowed to access this data
    response = requests.post(("http://127.0.0.1:" + str(SERVER_PORT) + "/key_request"), data=body)
    if response.status_code == 200:
        return response.json() #if the response is a success, return the public keys to the send method
    else:
        print("Failed to acquire keys. error:\n", str(response.text), "\n\n")

#basic encyption function
def encrypt(message, key):
    return key.encrypt(message.encode(), padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

#basic decryption
def decrypt(message, key):
    return key.decrypt(message, padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

#method to listen for new messages, runs in a thread concurrent to the sending method.
def listen(soc, key):
    while True:
        content = soc.recv(BUFFER_SIZE)
        name, message = content.split(b'|||') #"|||" is a special delimiter for this system. in this case it separates the name of the sender and the message
        name = name.decode("utf-8")
        message = decrypt(base64.b64decode(message), key)

        current_time_seconds = time.time()
        local_time = time.localtime(current_time_seconds)
        formatted_time = time.strftime("%H:%M:%S", local_time)

        print(name, formatted_time, "\n", message.decode(), "\n\n")
        #printed format:
        #sender HH:MM:SS
        #   message


def kick(target, port):
    body = {"origin": port, "target": target} # origin identifies the sender so the server can check permissions
    response = requests.post(("http://127.0.0.1:" + str(SERVER_PORT) + "/kick"), data=body)

    if response.status_code == 200:
        print(target, " was kicked successfully\n")
    else:
        print("Failed to kick ", target, ". error:\n", str(response.text), "\n\n")


def send(port):
    while True:
        message = input("")

        sys.stdout.write("\033[F")
        sys.stdout.write("\033[K")

        if message.startswith("|||"): #again we use ||| as a special delimiter, this time to indicate a kick command
            kick(message.removeprefix("|||"), port)

        else: #without the ||| indicator, the typed content is sent as a normal message
            try:
                keys = request_keys(port) #request the public keys of other members from the server so we can encrypt the message for each
                body = {}
                for key in keys.keys(): #for each other member, encrypt the message using their public key
                    encoded = encrypt(message, serialization.load_pem_public_key(keys[key].encode(), backend=default_backend()))
                    encoded = base64.b64encode(encoded).decode("utf-8")
                    body.update({key: encoded})

                body.update({"origin": port}) #origin indicates sender


                response = requests.post(("http://127.0.0.1:" + str(SERVER_PORT) + "/send"), data=body)

                if response.status_code != 200:
                    print("Failed to send. error:\n", str(response.text), "\n\n")

            except Exception as e:
                print(e)


def main(argv):
    name = argv[0]
    port = int(argv[1])
    skt = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    skt.bind(("127.0.0.1", port)) #a socket with which to listen for incoming messages

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()

    connect(public_key, name, port) #register with the server

    send_thread = threading.Thread(target=send, args=(port,))
    send_thread.start() #start a thread that reads inputs and forwards messages

    listen(skt, private_key)

if __name__ == "__main__":
    main(sys.argv[1:])
