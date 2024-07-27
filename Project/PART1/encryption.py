import numpy as np
from math import isqrt

def text_to_matrix(text, size):
    text_numeric = [ord(char) - 65 for char in text]
    return np.array(text_numeric).reshape(size, size)

def pad_message(message, key_size):
    padding_len = (key_size - len(message) % key_size) % key_size
    return message + 'X' * padding_len

key = input("Enter the Key: ").strip().upper()
message = input("Enter the Message: ").strip().upper()

key_len = len(key)
key_size = isqrt(key_len)
if key_size * key_size != key_len:
    print("Key is not square")
    exit()

message = pad_message(message, key_size)

key_matrix = text_to_matrix(key, key_size)
message_matrix = np.array([ord(char) - 65 for char in message]).reshape(-1, key_size).T

encrypted_matrix = np.dot(key_matrix, message_matrix) % 26
encrypted_message = ''.join(chr(num + 65) for num in encrypted_matrix.T.flatten())

print(encrypted_message)
