import secrets
#this is where we make the secret to use to check

def make_canary():
    return "CANARY-" + secrets.token_hex(8)