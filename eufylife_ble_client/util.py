from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def compute_checksum(data: bytearray) -> int:
    checksum = 0
    for byte in data:
        checksum ^= byte
    return checksum

def validate_checksum(data: bytearray) -> bool:
    checksum = data[-1]

    data_part = data[:-1]
    expected_checksum = compute_checksum(data_part)

    return checksum == expected_checksum

def encrypt_aes128cbc(data: bytes, key: bytes, iv: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted

def decrypt_aes128cbc(data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(data) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(decrypted) + unpadder.finalize()

def get_sub_contract_bytes(data_hex: str, prefix: str):
    result_list = []

    orig_length = len(data_hex)
    num_segments = orig_length // 30 + (0 if orig_length % 30 == 0 else 1)

    index = 0
    current_segment_num = 0
    while index < num_segments:
        start_index_in_src = index * 30
        index += 1
        data = f"{prefix}{num_segments:02x}{current_segment_num:02x}{orig_length // 2:02x}{data_hex[start_index_in_src:index * 30]}"
        data_with_checksum = f"{data}{compute_checksum(bytes.fromhex(data)):02x}"
        current_segment_num += 1
        result_list.append(data_with_checksum.upper())

    return result_list