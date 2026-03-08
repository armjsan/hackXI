import hashlib
import os
import secrets

# Large prime modulus to prevent integer overflow while preserving uniqueness
_MOD = (1 << 256) - 189


def _mat_mult_mod(A, B, mod):
    """Multiply two 4x4 matrices under modular arithmetic."""
    n = len(A)
    result = [[0] * n for _ in range(n)]
    for i in range(n):
        for j in range(n):
            for k in range(n):
                result[i][j] = (result[i][j] + A[i][k] * B[k][j]) % mod
    return result


def _mat_pow_mod(matrix, power, mod):
    """Matrix exponentiation by squaring under modular arithmetic."""
    n = len(matrix)
    # Start with identity matrix
    result = [[1 if i == j else 0 for j in range(n)] for i in range(n)]
    base = [row[:] for row in matrix]

    while power > 0:
        if power % 2 == 1:
            result = _mat_mult_mod(result, base, mod)
        base = _mat_mult_mod(base, base, mod)
        power //= 2

    return result


def generate_matrix_password(user_pw, random_n):
    # 1. Create a salted, hashed version of a random system component
    salt = os.urandom(16)
    system_pw = hashlib.sha256(salt + b"random_system_seed").hexdigest()

    # 2. Combine and prep data for a 4x4 matrix (16 elements)
    # We'll take the first 8 chars of user_pw and first 8 of system_pw
    combined_str = (user_pw[:8].ljust(8) + system_pw[:8])

    # Convert characters to integers (ASCII)
    data = [ord(char) for char in combined_str]

    # 3. Initialize the Matrix (pure Python lists for arbitrary precision)
    matrix = [data[i * 4:(i + 1) * 4] for i in range(4)]

    # 4. Matrix Power using modular exponentiation by squaring
    # Prevents integer overflow and runs in O(log n) multiplications
    final_matrix = _mat_pow_mod(matrix, random_n, _MOD)

    # 5. Finalize: Convert the matrix back to a unique hash string
    flat = b"".join(val.to_bytes(32, "big") for row in final_matrix for val in row)
    result_hash = hashlib.sha256(flat).hexdigest()

    return result_hash, salt


# Example Usage
n = secrets.randbelow(95) + 5  # Random power between 5 and 99
password, salt = generate_matrix_password("MyUserPass123", n)

print(f"Matrix Power: {n}")
print(f"Resulting 'True' Password: {password}")
