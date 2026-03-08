import hashlib
import os
import numpy as np

def generate_matrix_password(user_pw, random_n):
    # 1. Create a salted, hashed version of a random system component
    salt = os.urandom(16)
    system_pw = hashlib.sha256(salt + b"random_system_seed").hexdigest()
    
    # 2. Combine and prep data for a 4x4 matrix (16 elements)
    # We'll take the first 8 chars of user_pw and first 8 of system_pw
    combined_str = (user_pw[:8].ljust(8) + system_pw[:8])
    
    # Convert characters to integers (ASCII)
    data = [ord(char) for char in combined_str]
    
    # 3. Initialize the Matrix
    matrix = np.array(data).reshape(4, 4)
    
    # 4. Matrix Power (Matrix multiplication n times)
    # Note: Use matrix_power for true linear algebra power, not element-wise
    final_matrix = np.linalg.matrix_power(matrix, random_n)
    
    # 5. Finalize: Convert the matrix back to a unique hash string
    # We hash the string representation of the matrix to avoid floating point issues
    result_hash = hashlib.sha256(final_matrix.tobytes()).hexdigest()
    
    return result_hash, salt

# Example Usage
n = 5  # The random power
password, salt = generate_matrix_password("MyUserPass123", n)

print(f"Matrix Power: {n}")
print(f"Resulting 'True' Password: {password}")