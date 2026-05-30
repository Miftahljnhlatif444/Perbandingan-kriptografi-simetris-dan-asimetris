from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import time

# ==========================================
# Data yang akan dienkripsi
# ==========================================
plaintext = input("Masukkan teks yang akan dienkripsi: ")
data = plaintext.encode()

print("PLAINTEXT:")
print(plaintext)
print()

# ==========================================
# FERNET (SIMETRIS)
# ==========================================
print("===== FERNET (SIMETRIS) =====")

# Generate key
fernet_key = Fernet.generate_key()
fernet = Fernet(fernet_key)

# Enkripsi
start_encrypt = time.perf_counter()
fernet_ciphertext = fernet.encrypt(data)
end_encrypt = time.perf_counter()

encrypt_time_fernet = end_encrypt - start_encrypt

# Dekripsi
start_decrypt = time.perf_counter()
fernet_plaintext = fernet.decrypt(fernet_ciphertext)
end_decrypt = time.perf_counter()

decrypt_time_fernet = end_decrypt - start_decrypt

print("Ciphertext:")
print(fernet_ciphertext.decode())
print()

print("Hasil Dekripsi:")
print(fernet_plaintext.decode())
print()

# ==========================================
# RSA (ASIMETRIS)
# ==========================================
print("===== RSA (ASIMETRIS) =====")

# Generate key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

public_key = private_key.public_key()

# Enkripsi
start_encrypt = time.perf_counter()
rsa_ciphertext = public_key.encrypt(
    data,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
end_encrypt = time.perf_counter()

encrypt_time_rsa = end_encrypt - start_encrypt

# Dekripsi
start_decrypt = time.perf_counter()
rsa_plaintext = private_key.decrypt(
    rsa_ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
end_decrypt = time.perf_counter()

decrypt_time_rsa = end_decrypt - start_decrypt

print("Ciphertext (byte):")
print(rsa_ciphertext)
print()

print("Hasil Dekripsi:")
print(rsa_plaintext.decode())
print()

# ==========================================
# HASIL PENGUJIAN
# ==========================================
print("===== HASIL PENGUJIAN =====")

print(f"Ukuran Plaintext  : {len(data)} byte")
print(f"Ukuran Ciphertext Fernet : {len(fernet_ciphertext)} byte")
print(f"Ukuran Ciphertext RSA    : {len(rsa_ciphertext)} byte")
print()

print(f"Waktu Enkripsi Fernet : {encrypt_time_fernet:.8f} detik")
print(f"Waktu Dekripsi Fernet : {decrypt_time_fernet:.8f} detik")
print()

print(f"Waktu Enkripsi RSA : {encrypt_time_rsa:.8f} detik")
print(f"Waktu Dekripsi RSA : {decrypt_time_rsa:.8f} detik")
print()

# ==========================================
# TABEL PERBANDINGAN
# ==========================================
print("===== TABEL PERBANDINGAN =====")

print("{:<20} {:<20} {:<20}".format("Kriteria", "Fernet (AES)", "RSA"))
print("-" * 60)

print("{:<20} {:<20} {:<20}".format(
    "Jenis Kunci",
    "1 Kunci",
    "Public & Private"
))

print("{:<20} {:<20} {:<20}".format(
    "Kecepatan",
    "Sangat Cepat",
    "Lebih Lambat"
))

print("{:<20} {:<20} {:<20}".format(
    "Ukuran Cipher",
    str(len(fernet_ciphertext)) + " byte",
    str(len(rsa_ciphertext)) + " byte"
))

print("{:<20} {:<20} {:<20}".format(
    "Keamanan Dasar",
    "Tinggi",
    "Tinggi"
))

print("{:<20} {:<20} {:<20}".format(
    "Kegunaan",
    "Data besar",
    "Pertukaran kunci"
))