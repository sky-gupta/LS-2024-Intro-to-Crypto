import numpy as np
from math import gcd

def gaussian_elimination(a, b):
    size = len(a)  
    augmented_matrix = np.hstack((a, b)).astype(float) 
    
    for i in range(size):
        if augmented_matrix[i][i] == 0.0: 
            for j in range(i + 1, size):
                if augmented_matrix[j][i] != 0.0:
                    augmented_matrix[[i, j]] = augmented_matrix[[j, i]]
                    break

        augmented_matrix[i] /= augmented_matrix[i][i] 

        for j in range(i + 1, size):  
            augmented_matrix[j] -= augmented_matrix[i] * augmented_matrix[j][i]

    for i in range(size - 1, -1, -1):
        for j in range(i - 1, -1, -1):
            augmented_matrix[j] -= augmented_matrix[i] * augmented_matrix[j][i]
    
    solution_matrix = augmented_matrix[:, size:]
    return solution_matrix

def pad_matrix(text):
    text_length = len(text)
    if text_length % 3 != 0:
        text += "X" * (3 - text_length % 3) 
    text_matrix = np.array([ord(char) - 65 for char in text]).reshape(-1, 3) 
    return text_matrix

def key_matrix_search(plain_mat, cipher_mat):
    column_count = len(cipher_mat)
    for i in range(column_count):
        for j in range(i + 1, column_count):
            for k in range(j + 1, column_count):
                sub_matrix = np.column_stack((plain_mat[i], plain_mat[j], plain_mat[k])).astype(float)
                det = round(np.linalg.det(sub_matrix)) 
                if gcd(det, 26) == 1:  
                    cofactor_mat = np.array([[(sub_matrix[(row+1)%3][(col+1)%3]*sub_matrix[(row+2)%3][(col+2)%3] - sub_matrix[(row+1)%3][(col+2)%3]*sub_matrix[(row+2)%3][(col+1)%3]) for row in range(3)] for col in range(3)]) % 26
                    temp_key = np.column_stack((cipher_mat[i], cipher_mat[j], cipher_mat[k])).astype(int) % 26
                    temp_key = np.matmul(temp_key, cofactor_mat)  
                    temp_key *= pow(det, -1, 26) 
                    temp_key %= 26  
                    return temp_key
    return None

def brute_force_key_search(plain_mat, cipher_mat, row_idx):
    potential_keys = []
    result_vector = cipher_mat.T[row_idx]
    for col in range(len(cipher_mat)):
        for idx in range(3):
            if plain_mat[col][idx] % 2 == 0 or plain_mat[col][idx] % 13 == 0:
                continue 
            first_row, second_row = [x for x in range(3) if x != idx]
            for i in range(26):
                for j in range(26):
                    k = ((cipher_mat[col][row_idx] - i * plain_mat[col][first_row] - j * plain_mat[col][second_row]) * pow(int(plain_mat[col][idx]), -1, 26)) % 26
                    key_vec = np.array([i, j, k]) if idx == 0 else np.array([j, k, i]) if idx == 1 else np.array([k, i, j])
                    if np.array_equal(np.matmul(key_vec, plain_mat.T) % 26, result_vector):
                        potential_keys.append(key_vec)
    return potential_keys

def main():
    plaintext = input("Enter the plaintext: ").strip().upper()
    ciphertext = input("Enter the Ciphertext: ").strip().upper()
    plain_matrix = pad_matrix(plaintext)
    cipher_matrix = pad_matrix(ciphertext)
    
    key_matrix = key_matrix_search(plain_matrix, cipher_matrix)
    if key_matrix is not None:
        print("Key Matrix:\n", key_matrix)
        key_string = "".join([chr(int(round(char)) + 65) for char in key_matrix.flatten()])
        print("Key String:", key_string)
        return

    potential_key_matrices = []
    for row in range(3):
        potential_key_matrices.append(brute_force_key_search(plain_matrix, cipher_matrix, row))

    for key_1 in potential_key_matrices[0]:
        for key_2 in potential_key_matrices[1]:
            for key_3 in potential_key_matrices[2]:
                combined_key = np.column_stack((key_1, key_2, key_3))
                print("Potential Key Matrix:\n", combined_key)

if __name__ == "__main__":
    main()
