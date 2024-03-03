#################################################
# @File AES Encryption Functions Using no       #
#       external libraries                      #
#################################################

Sbox = [
            [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
            [0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],
            [0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],
            [0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],
            [0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],
            [0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],
            [0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],
            [0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],
            [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],
            [0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],
            [0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],
            [0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],
            [0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],
            [0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],
            [0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],
            [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]
        ]

# Takes a string and a key as input and returns its aes encrypted output
def AES_encrypt(plaintext: str, key: str, type: int) -> str:
    f_data = format_input(plaintext, type)
    exp_key = expand_key(key)
    out_data = []
    for x in f_data:
        out_data.append(aes_encrypt_block(x, exp_key, type))
    ciphertext = format_output(out_data)
    return ciphertext

# Formats a string into a list of blocks that AES can operate on
def format_input(data: str, type: int) -> list[list[list[int]]]:
    # Pad the input string if its length is not a multiple of 16
    padded_string = data.ljust((len(data) + 15) // 16 * 16)

    if type == 128:
        # Split the padded string into chunks of 16 characters
        chunks = [padded_string[i:i+16] for i in range(0, len(padded_string), 16)]
        # Convert each chunk into a 4x4 matrix of integers
        matrices = []
        for chunk in chunks:
            matrix = []
            for i in range(0, len(chunk), 4):
                matrix.append([ord(char) for char in chunk[i:i+4]])
            matrices.append(matrix)
    elif type == 192:
        # For AES-192, create 4x6 matrices
        chunks = [padded_string[i:i+24] for i in range(0, len(padded_string), 24)]
        matrices = []
        for chunk in chunks:
            matrix = []
            for i in range(0, len(chunk), 4):
                matrix.append([ord(char) for char in chunk[i:i+4]])
            matrices.append(matrix)
    elif type == 256:
        # For AES-256, create 4x8 matrices
        chunks = [padded_string[i:i+32] for i in range(0, len(padded_string), 32)]
        matrices = []
        for chunk in chunks:
            matrix = []
            for i in range(0, len(chunk), 4):
                matrix.append([ord(char) for char in chunk[i:i+4]])
            matrices.append(matrix)
    else:
        raise ValueError("Invalid AES type. Supported types are 128, 192, and 256.")

    return matrices

# Formats the output of AES encryption back to a string
def format_output(matrices: list[list[list[int]]]) -> str:
    characters = []
    for matrix in matrices:
        for row in matrix:
            for char_code in row:
                characters.append(chr(char_code))

    output_string = ''.join(characters)
    output_string = output_string.rstrip(chr(0))

    return output_string

# Encrypts one block of data
def aes_encrypt_block(mat: list[list[int]], exp_key: list[list[list[bytes]]], type: int) -> list[list[int]]:
    num_rounds = 0
    if(type == 128):
        num_rounds = 10
    elif(type == 192):
        num_rounds = 12
    elif(type == 256):
        num_rounds = 14
    else:
        return None
    
    for i in range(num_rounds):
        if(i == 0):
            mat = add_roundkey(mat, exp_key[i])
        elif(i == (num_rounds - 1)):
            mat = do_last_round(mat, exp_key[i])
        else:
            mat = do_round(mat, exp_key[i])
    return mat 

# Does a round of AES
def do_round(mat: list[list[int]], roundkey: list[list[bytes]]) -> list[list[int]]:
    mat = sub_bytes(mat)
    mat = shift_rows(mat)
    mat = mix_columns(mat)
    mat =  add_roundkey(mat, roundkey)

    return mat

# Does the last round of AES omitting shiftcolumns
def do_last_round(mat: list[list[int]], roundkey: list[list[bytes]]) -> list[list[int]]:
    mat = sub_bytes(mat)
    mat = shift_rows(mat)
    mat =  add_roundkey(mat, roundkey)

    return mat

# First step of AES round
def sub_bytes(mat: list[list[int]]) -> list[list[int]]:
    for x in range(4):
        for y in range(4):
            left_bits = mat[x][y] & 0xF0 >> 4
            right_bits = mat[x][y] & 0x0F
            mat[x][y] = Sbox[left_bits][right_bits]

    return mat

# Second step of AES round
def shift_rows(mat: list[list[int]]) -> list[list[int]]:
    mat[1] = mat[1][1:] + mat[1][:1]
    mat[2] = mat[2][2:] + mat[2][:2]
    mat[3] = mat[3][3:] + mat[3][:3]
    return mat

#  Third step of AES round
def mix_columns(mat: list[list[int]], type: int) -> list[list[int]]:
    if(type == 128):
        for i in range(4):
            s0 = mat[0][i]
            s1 = mat[1][i]
            s2 = mat[2][i]
            s3 = mat[3][i]

            mat[0][i] = galois_multiply(2, s0) ^ galois_multiply(3, s1) ^ s2 ^ s3
            mat[1][i] = s0 ^ galois_multiply(2, s1) ^ galois_multiply(3, s2) ^ s3
            mat[2][i] = s0 ^ s1 ^ galois_multiply(2, s2) ^ galois_multiply(3, s3)
            mat[3][i] = galois_multiply(3, s0) ^ s1 ^ s2 ^ galois_multiply(2, s3)
    elif(type == 192):
            s0 = mat[0][i]
            s1 = mat[1][i]
            s2 = mat[2][i]
            s3 = mat[3][i]

            mat[0][i] = galois_multiply(2, s0) ^ galois_multiply(3, s1) ^ s2 ^ s3
            mat[1][i] = s0 ^ galois_multiply(2, s1) ^ galois_multiply(3, s2) ^ s3
            mat[2][i] = s0 ^ s1 ^ galois_multiply(2, s2) ^ galois_multiply(3, s3)
            mat[3][i] = galois_multiply(3, s0) ^ s1 ^ s2 ^ galois_multiply(2, s3)
    return mat

# Fourth step of AES round
def add_roundkey(mat: list[list[int]], roundkey: list[list[bytes]]):
    for i in range(4):
        for j in range(4):
            val = roundkey[i][j] ^ mat[i][j]
            mat[i][j] = val

    return mat

# Function to handle key expansion
def expand_key(key: str) -> list[list[list[bytes]]]:
    key = bytearray(key.encode())
    key_mat = [bytearray]
    num_rounds = 0
    size_index = 0
    if(len(key) == 16):
        key_mat = [key[i*4:(i*4)+4] for i in range(4)]
        num_rounds = 10
        size_index = 4
    elif(len(key) == 24):
        key_mat = [key[i*4:(i*4)+4] for i in range(6)]
        num_rounds = 12
        size_index = 6
    elif(len(key) == 32):
        key_mat = [key[i*4:(i*4)+4] for i in range(8)]
        num_rounds = 14
        size_index = 8
    else:
        return None
    
    seed = []
    for x in range(size_index):
        seed.append(sum(key_mat[x]).to_bytes(4, 'big'))
    raw_key = expander(seed, num_rounds, size_index)
    extended_key = format_key(raw_key, (size_index*4))
    return extended_key

# Key expansion helper
def format_key(expanded_key: list[list[bytearray]], type: int) -> list[list[list[bytes]]]:
    long_bytearray = bytearray()
    for sublist in expanded_key:
        for byte_arr in sublist:
            long_bytearray.extend(byte_arr)
    
    group_size = 16 * (type // 32)  # Adjust group size based on AES type
    formatted_groups = [long_bytearray[i:i+group_size] for i in range(0, len(long_bytearray), group_size)]
    
    extended_key = []
    for group in formatted_groups:
        matrix = []
        for i in range(0, len(group), 4):
            matrix.append(list(group[i:i+4]))
        extended_key.append(matrix)
    
    return extended_key

# Key expansion helper          
def expander(seed: list[bytearray], num_rounds, size_index) -> list[list[bytearray]]:
    expanded = [0] * (num_rounds + 1)
    expanded[0] = seed
    for i in range(num_rounds):
        expanded[i+1] = expander_step(expanded[i], i+1, size_index)
    return(expanded)

# Key expansion helper     
def expander_step(prev: list[bytearray], rnd, size_index) -> list[bytearray]:
    out = [0] * size_index
    w_3_prime = g_box(prev[-1], rnd)
    for i in range(size_index):
        if(i == 0):
            out[i] = bytearray(a ^ b for a, b in zip(w_3_prime, prev[0]))
        else:
            out[i] = bytearray(a ^ b for a, b in zip(out[i-1], prev[i]))
    
    return out

# Key expansion helper     
def g_box(word: bytearray, rnd) -> bytearray:
    Rcon_lst = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 
                0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 
                0x4d]
    rcon = bytearray([Rcon_lst[rnd], 0x00, 0x00, 0x00])
    byte_1 = word[0]
    word = int.from_bytes(word, "big") 
    temp = ((word << 8) |  byte_1) & 0x00FFFFFFFF
    word = int.to_bytes(temp, length=4, byteorder="big")
    word = [Sbox[(x & 0xF0) >> 4][x & 0x0F] for x in word]
    word = bytearray(a ^ b for a, b in zip(word, rcon))

    return word

# Multiplication in a galois field
def galois_multiply(a, b):
    """Galois Field multiplicaiton for AES"""
    p = 0
    while b:
        if b & 1:
            p ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x1b
        b >>= 1

    return p & 0xff

# Takes a string and a key as input and returns its AES decrypted output
def AES_decrypt(ciphertext: str, key: str, type: int) -> str:
    f_data = format_input(ciphertext, type)
    exp_key = expand_key(key)
    out_data = []
    for x in f_data:
        out_data.append(aes_decrypt_block(x, exp_key, type))
    plaintext = format_output(out_data)
    return plaintext

# Decrypts one block of data
def aes_decrypt_block(mat: list[list[int]], exp_key: list[list[list[bytes]]], type: int) -> list[list[int]]:
    num_rounds = 0
    if(type == 128):
        num_rounds = 10
    elif(type == 192):
        num_rounds = 12
    elif(type == 256):
        num_rounds = 14
    else:
        return None
    
    for i in range(num_rounds, 0, -1):
        if(i == num_rounds):
            mat = do_last_round_decrypt(mat, exp_key[i])
        else:
            mat = do_round_decrypt(mat, exp_key[i])
    mat = add_roundkey(mat, exp_key[0])  # Final round with initial key
    return mat

# Does a round of AES decryption
def do_round_decrypt(mat: list[list[int]], roundkey: list[list[bytes]]) -> list[list[int]]:
    mat = inv_shift_rows(mat)
    mat = inv_sub_bytes(mat)
    mat =  add_roundkey(mat, roundkey)
    mat = inv_mix_columns(mat)

    return mat

# Does the last round of AES decryption omitting inv_shift_columns
def do_last_round_decrypt(mat: list[list[int]], roundkey: list[list[bytes]]) -> list[list[int]]:
    mat = inv_shift_rows(mat)
    mat =  add_roundkey(mat, roundkey)

    return mat

# Inverse of shift_rows
def inv_shift_rows(mat: list[list[int]]) -> list[list[int]]:
    mat[1] = mat[1][-1:] + mat[1][:-1]
    mat[2] = mat[2][-2:] + mat[2][:-2]
    mat[3] = mat[3][-3:] + mat[3][:-3]
    return mat

def inv_sub_bytes(mat: list[list[int]]) -> list[list[int]]:
    for x in range(4):
        for y in range(4):
            byte_value = mat[x][y]
            row = (byte_value & 0xF0) >> 4
            col = byte_value & 0x0F
            mat[x][y] = Sbox[row][col]

    return mat

# Inverse of mix_columns
def inv_mix_columns(mat: list[list[int]]) -> list[list[int]]:
    for i in range(4):
        s0 = mat[0][i]
        s1 = mat[1][i]
        s2 = mat[2][i]
        s3 = mat[3][i]

        mat[0][i] = galois_multiply(0x0e, s0) ^ galois_multiply(0x0b, s1) ^ galois_multiply(0x0d, s2) ^ galois_multiply(0x09, s3)
        mat[1][i] = galois_multiply(0x09, s0) ^ galois_multiply(0x0e, s1) ^ galois_multiply(0x0b, s2) ^ galois_multiply(0x0d, s3)
        mat[2][i] = galois_multiply(0x0d, s0) ^ galois_multiply(0x09, s1) ^ galois_multiply(0x0e, s2) ^ galois_multiply(0x0b, s3)
        mat[3][i] = galois_multiply(0x0b, s0) ^ galois_multiply(0x0d, s1) ^ galois_multiply(0x09, s2) ^ galois_multiply(0x0e, s3)
    return mat
