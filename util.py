import json
import settings

def create_algorithm_header_client(supported_algorithms, public_key_len, name):
    header = {
        'supported_algorithms': supported_algorithms,
        'public_key_len': public_key_len,
        'name': name
    }

    data = json.dumps(header)
    data = data.encode()
    if len(data) > settings.HANDHSAKE_HEADER_LEN:
        raise Exception("header is too long!")

    # add padding, so the message is the correct length
    return data.ljust(settings.HANDHSAKE_HEADER_LEN)

def create_algorithm_header_server(picked_algorithm, public_key_len, name):
    header = {
        'algorithm': picked_algorithm,
        'public_key_len': public_key_len,
        'name': name
    }

    data = json.dumps(header)
    data = data.encode()
    if len(data) > settings.HANDHSAKE_HEADER_LEN:
        raise Exception("header is too long!")
    
    # add padding, so the message is the correct length
    return data.ljust(settings.HANDHSAKE_HEADER_LEN)

# pick the strongest algorithm from the clients configuration
def pick_algorithm(strong_algorithms, client_config):
    client_algorithms = client_config['supported_algorithms']
    for alg in strong_algorithms:
        if alg in client_algorithms:
            return alg
        
    return None

# print a message from a peer and keep the current cursor position
# in the console.
# credit: https://stackoverflow.com/questions/75507228/python-print-message-while-asking-user-for-input
def print_message(msg):
    lines = msg.split('\n')
    for line in lines:
        print(
            "\u001B[s"             # Save current cursor position
            "\u001B[A"             # Move cursor up one line
            "\u001B[999D"          # Move cursor to beginning of line
            "\u001B[S"             # Scroll up/pan window down 1 line
            "\u001B[L",            # Insert new line
        end="")     
        print(line, end="")
        print("\u001B[u", end="")  # Move back to the former cursor position
        print("", end="", flush=True)  # Flush message
