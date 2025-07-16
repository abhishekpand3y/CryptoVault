from flask import current_app
import os
import json

KEYS_FILE = os.environ.get('KEYS_FILE', 'aes_keys.json')

def load_keys():
    if not os.path.exists(KEYS_FILE):
        # Initialize with current AES_KEY as version 1
        keys = {"1": current_app.config['AES_KEY']}
        with open(KEYS_FILE, 'w') as f:
            json.dump(keys, f)
        return keys
    with open(KEYS_FILE, 'r') as f:
        return json.load(f)

def save_keys(keys):
    with open(KEYS_FILE, 'w') as f:
        json.dump(keys, f)

def get_key(version):
    keys = load_keys()
    return keys[str(version)]

def get_latest_key_version():
    keys = load_keys()
    return int(max(keys.keys(), key=int))

def rotate_keys(new_key):
    keys = load_keys()
    new_version = str(get_latest_key_version() + 1)
    keys[new_version] = new_key
    save_keys(keys)
    return int(new_version) 