import socket
from flask import Flask, request, jsonify, make_response
import threading
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

SERVER_PORT = 5000
members = {} # {port: public key}
names = {} # {port: name}
global admin
admin = None # tracks who is admin based on their port number

app = Flask(__name__)
svr_skt = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
svr_skt.bind(("127.0.0.1", 5001)) # socket for forwarding messages

# called by clients that want to connect to the server
@app.route("/connect", methods=["POST"])
def accept_connection():
    global admin
    try:
        username = request.form.get("name")
        if username in names.values(): # if a user joins with an already existing name, we append a number to differentiate
            n = 0
            for key in names.keys():
                if names[key] == username or (names[key][:len(names[key])-4] == username):
                    n += 1
            username += " (" + str(n) + ")"

        user_port = request.form.get("port")
        key = request.form.get("public_key")

        if len(members) == 0: # if there are no members currently on the server, the new member is made admin
            admin = user_port

        members.update({user_port: key})
        names.update({user_port: username})

        response_data = make_response("Account created successfully for " + username + " on port " + str(user_port))
        response_data.status_code = 200

    except Exception as e:
        print(e)
        response_data = make_response(str(e))
        response_data.status_code = 400

    return response_data

#called by clients that want to access the other users' public keys
@app.route("/key_request", methods=["POST"])
def return_keys():
    sender = request.form.get("origin")
    if sender not in members.keys(): # if we don't recognise the client, we don't give them the keys
        response = make_response("unauthorised user")
        response.status_code = 403
        return response

    try:
        response = jsonify(members)
        response.status_code = 200
        response.headers["Content-Type"] = "application/json"

    except Exception as e:
        print(e)
        response = make_response(str(e))
        response.status_code = 400

    return response

#called by clients that wish to send a message
@app.route("/send", methods=["POST"])
def forward():
    sender = request.form.get("origin")
    if sender not in members.keys(): # if we don't recognise the client we don't forward their message
        response = make_response("unauthorised user")
        response.status_code = 403
        return response

    try:
        sender = names[sender] + "|||" # we append our special delimiter to the name so we can send the name and message as one packet and the clients can separate them
        for member in members.keys():
            body = request.form.get(member)
            svr_skt.sendto((sender.encode("utf-8") + body.encode("utf-8")), ("127.0.0.1", int(member)))

        response = make_response("")
        response.status_code = 200

    except Exception as e:
        print(e)
        response = make_response(str(e))
        response.status_code = 400

    return response

#called by clients that attempt to kick another user
@app.route("/kick", methods=["POST"])
def kick():
    global admin
    sender = request.form.get("origin")
    if sender not in members.keys():
        response = make_response("unauthorised user")
        response.status_code = 403
        return response

    try:
        target = request.form.get("target")
        response = {}
        if sender == admin: # only the admin can disconnect other users
            if target == names[admin]: # if the admin is disconnecting themselves, we assign the second oldest user as the new admin
                for key in members.keys():
                    admin = key
                    break
            if target in names.values(): # make sure the target actually exists
                for key, value in names.items():
                    if value == target:
                        del members[key]
                        del names[key]
                        break
            else: # if the target doesn't exist
                response = make_response("that user does not exist")
                response.status_code = 404
        else: # if someone other than the admin attempts a kick
            if names[sender] == target: # if they want to disconnect themselves
                for key, value in names.items():
                    if value == target:
                        del members[key]
                        del names[key]
                        break
            else: # if they want to disconnect someone else
                response = make_response("you do not have permission to disconnect other users")
                response.status_code = 403

    except Exception as e:
        print(e)
        response = make_response(str(e))
        response.status_code = 400

    return response


if __name__ == "__main__":
    app.config['PROPAGATE_EXCEPTIONS'] = True
    app.run(host="127.0.0.1", port=SERVER_PORT)
