# This file contains the code for displaying the messages, interacting with
# the console and managing all connections.
# The code where all encryption stuff occurs is inside `hai_core.py`.
import hai_core
import selectors
import settings
import socket
import sys
import util

### Global variables / state ###

HAI_STATE = {
    "current_client": None,
    "cwd": "~/chats/",
    "host": "",
    "port": 0,
    "name": ""
}

active_connections = {}
# use non-blocking sockets to manage multiple connections
sel = selectors.DefaultSelector()

### Messages ###
    
def send_message_to_current_client(msg):
    if len(active_connections) == 0:
        print("[INFO]: No connections yet! Use the `:connect` command to " \
              "connect to another HAI intance")
        return
    elif HAI_STATE["current_client"] is None:
        print("[INFO]: Not chatting to anyone at this moment. Use the `:cd` " \
              "command to pick someone to chat with")
        return

    # normalize message endings
    msg = msg.rstrip('\r\n')

    client = HAI_STATE["current_client"]
    conf = active_connections[client]
    key_data = conf["key_data"]
    conn = conf["conn"]

    try:
        hai_core.send(conn, msg, key_data)
    except Exception as e:
        print(f"[ERROR]: error while sending message: {e}")

def handle_incoming_message(conn, name):
    conf = active_connections[name]
    key_data = conf["key_data"]

    try:
        msg = hai_core.recv(conn, key_data)
        if msg is not None:
            msg = f"{name}: {msg}"
            util.print_message(msg)
    except Exception as e:
        # close the connection when an error occurred or when the connection
        # was closed/needs to be closed
        if str(e) == "Unexpected close":
            util.print_message(f"[INFO]: \"{name}\" unexpectedly closed the " \
                               "connection")
            util.print_message(f"[INFO]: Closing connection with \"{name}\" ...")
        elif str(e) == "Closed connection":
            util.print_message(f"[INFO]: \"{name}\" wants to close the " \
                               "connection")
        else:
            util.print_message(f"[ERROR]: error while receiving a message from" \
                               f"\"{name}\": {e}")
            util.print_message(f"[INFO]: Closing connection with \"{name}\" ...")

        if HAI_STATE["current_client"] == name:
            HAI_STATE["current_client"] = None
            HAI_STATE["cwd"] = "~/chats/"
        
        # first remove the connection from event loop, then close the connection
        sel.unregister(conn)
        active_connections.pop(name)
        
        conn.close()
        util.print_message(f"[INFO]: Connection with \"{name}\" is closed")

### Commands ###
        
def handle_command(cmd):
    if cmd.startswith("connect"):
        connect_to(cmd)
    elif cmd == "ls":
        do_ls()
    elif cmd == "info":
        show_info()
    elif cmd == "help":
        show_help()
    elif cmd.startswith("cd"):
        do_cd(cmd)
    elif cmd == "close":
        do_close()
    else:
        print(f"Unkown command \"{cmd}\"")
        show_help()

def do_ls():
    if HAI_STATE['cwd'].startswith("~/chats/"):
        if len(active_connections) == 0:
            print("No connections yet! Use the `:connect` command to connect " \
                  "to another HAI intance")
        else:
            for name, data in active_connections.items():
                addr = data["conn"].getpeername()
                print(f"\"{name}\": connected to {addr}")

def do_cd(cmd):
    if len(cmd) < 4:
        print("Usage: `:cd [path]`")
        return
    
    path = cmd[3:].rstrip('\r\n')
    
    if path.startswith("~/chats/") or HAI_STATE["cwd"].startswith("~/chats/"):
        # get client name
        parts = path.split("~/chats/")
        client = parts[0]
        if len(parts) == 2:
            client = parts[1]

        # check if a connection witht that name exists
        if client in active_connections:
            HAI_STATE["current_client"] = client
            HAI_STATE["cwd"] = f"~/chats/{client}"
        else:
            print(f"No client with name \"{client}\" exists!")
    else:
        print(f"Invalid path \"{path}\"!")

def show_info():
    print(f"""HAI INFO:
Accepting incoming connections at {HAI_STATE["host"]}:{HAI_STATE["port"]}
There are currently {len(active_connections)} active chats""")
    
    if HAI_STATE["current_client"] is not None:
        client = HAI_STATE["current_client"]
        key_data = active_connections[client]["key_data"]

        print(f"\nCurrently chatting with {client}\n. Own public key:")
        print(key_data["own_public_key_pem"].decode('ascii'))
        
        print(f"\"{client}\"'s public key:")
        print(key_data["client_public_key_pem"].decode('ascii'))

        print(f"Currently used keys for encrypting own mesages :")
        print(f'key: {key_data["own_aes_data"]["key"].hex()}\n' \
              f'iv: {key_data["own_aes_data"]["iv"].hex()}')
        
        print("\nCurrently used keys for decrypting mesages:")
        print(f'key: {key_data["client_aes_data"]["key"].hex()}\n' \
              f'iv: {key_data["client_aes_data"]["iv"].hex()}')

def show_help():
    print("All commands start with a colon ':'. Else the text will be sent " \
"as a message to the currently connected client. You can see which client you" \
" are chatting with by looking " \
"""at the current path.
:connect [server]:[port]\tConnect to another HAI instance.
:close\t\t\t\tClose the connection to the current client
:ls\t\t\t\tShow the current chats
:cd [name]\t\t\tChat to another client
:help\t\t\t\tThis message\n""" \
":info\t\t\t\tDisplay information about the current status, chat "\
"public keys and aes keys and initalization vectors.")
    
def connect_to(raw_cmd):
    if len(raw_cmd) < 10:
        print("Usage: `:connect [server]:[port]`")
        return

    [server, port] = raw_cmd[8:].split(':')
    port = int(port)
    print(f"[INFO]: Trying to connect to '{server}':'{port}'")

    conn = socket.create_connection(('localhost', port))
    print(f"[INFO]: Connected to {server}:{port}. Starting the handshake")
    try:
        (name, key_data) = hai_core.do_client_handshake(conn, HAI_STATE["name"])
        active_connections[name] = {
            "conn": conn,
            "key_data": key_data
        }
        
        HAI_STATE["current_client"] = name
        HAI_STATE["cwd"] = f"~/chats/{name}"
        sel.register(conn, selectors.EVENT_READ, name)

        print(f"[INFO]: Handshake verified! Further communication with " \
              f"\"{name}\" is now encrypted!")
        print(f"[INFO]: You can now start chatting!")
    except Exception as e:
        print(f"[INFO]: Invalid handshake! Closing connection... {e}")
        conn.close()

def do_close():
    if len(active_connections) == 0:
        print("[INFO]: No connections yet! Use the `:connect` command to " \
              "connect to another HAI intance")
        return
    elif HAI_STATE["current_client"] is None:
        print("[INFO]: Not chatting to anyone at this moment. Use the `:cd` " \
              "command to pick someone to chat with")
        return

    client = HAI_STATE["current_client"]
    conf = active_connections[client]
    key_data = conf["key_data"]
    conn = conf["conn"]

    print(f"[INFO]: Trying to close the connection to \"{client}\"")

    sel.unregister(conn)        
    try:
        hai_core.close(conn, key_data)
    except Exception as e:
        print(f"[ERROR]: failed to properly close connection: {e}")

    if HAI_STATE["current_client"] == client:
        HAI_STATE["current_client"] = None
        HAI_STATE["cwd"] = "~/chats/"

    active_connections.pop(client)
    util.print_message(f"[INFO]: Connection with \"{client}\" is closed")

### Socket Server ###

def bind_and_listen(host, port):
    sock = socket.create_server((host, port), family=socket.AF_INET, 
                                backlog=128, reuse_port=True)
    sock.setblocking(False)

    print(f"[INFO]: Started listening on {host}:{port}")

    return sock

def handle_new_connection(sock):
    conn, addr = sock.accept()
    util.print_message(f"[INFO]: Accepted connection from {addr[0]}:{addr[1]}")
    try:
        (name, key_data) = hai_core.do_server_handshake(
            conn, addr, HAI_STATE["name"])

        active_connections[name] = {
            "conn": conn,
            "key_data": key_data
        }
        HAI_STATE["current_client"] = name
        HAI_STATE["cwd"] = f"~/chats/{name}"

        sel.register(conn, selectors.EVENT_READ, name)
    except Exception as e:
        util.print_message(f"[INFO]: invalid handshake from client " \
                           f"{addr[0]}:{addr[1]}. Closing connection... {e}")
        conn.close()
        return

### Non-blocking socket stuff ###
    
def loop_once():
    events = sel.select()
    for key, mask in events:
        if mask & selectors.EVENT_READ:
            read_event(key.fileobj, key.data, mask)

def read_event(sock, data, mask):
    # data is not set, so it is a new socket. We must accept the new 
    # connection first.
    if sock == sys.stdin:
        read_input()
    elif data is None:
        handle_new_connection(sock)
    else:
        handle_incoming_message(sock, data)

def read_input():
    line = sys.stdin.readline()

    if line.startswith(':'):
        handle_command(line[1:].strip())
    else:
        send_message_to_current_client(line)

    print_cmd_line()
        
def print_cmd_line():
    print(f"[{HAI_STATE['cwd']}] > ", end="", flush=True)

### Startup ###

def print_startup_message():
    print("\nWelcome to Hai! The 100% console based secure messaging program.\n")
    show_help()
    print("\nPlease provide the following information to get started:\n")
    

def main():
    print_startup_message()

    host = settings.HOST
    port = input("Listening port: ")
    name = input("Identifying name: ")
    HAI_STATE["host"] = host
    HAI_STATE["port"] = port
    HAI_STATE["name"] = name

    sock = bind_and_listen(host, int(port))
    
    # add the listening socket to the event loop
    print(f"[{HAI_STATE['cwd']}] > ", end="", flush=True)
    sel.register(sys.stdin, selectors.EVENT_READ)
    sel.register(sock, selectors.EVENT_READ)

    try:
        while True:
            loop_once()
    except KeyboardInterrupt:
        print("Closing server. Sending close message to all connected clients")
        # send close message to all active connections
        for name, conf in active_connections.items():
            conn = conf["conn"]
            sel.unregister(conn)
            hai_core.close(conn, conf["key_data"])

if __name__ == "__main__":
    main()
