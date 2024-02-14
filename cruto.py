# Définition des fonctions de rotation et d'addition modulaire
def rotate_left(val, r_bits, max_bits):
    return (val << r_bits % max_bits) & (2 ** max_bits - 1) | ((val & (2 ** max_bits - 1)) >> (max_bits - (r_bits % max_bits)))

def addition_modulo(val1, val2, max_bits):
    return (val1 + val2) % (2 ** max_bits)

# Fonction principale de génération de la séquence Salsa20
def salsa20(key, nonce, counter):
    # Initialisation des variables de l'état interne
    state = [0] * 16
    state[1], state[6], state[11], state[12] = key[:4]
    state[2], state[5], state[10], state[15] = key[4:8]
    state[3], state[4], state[9], state[14] = key[8:12]
    state[0], state[7], state[8], state[13] = key[12:16]
    state[5] = addition_modulo(state[5], rotate_left(counter, 32, 32), 32)
    state[6] = addition_modulo(state[6], rotate_left(counter >> 32, 32, 32), 32)

    # Itérations de diffusion
    for _ in range(10):
        state[4] ^= rotate_left(addition_modulo(state[0] + state[12], 32, 32), 7, 32)
        state[8] ^= rotate_left(addition_modulo(state[4] + state[0], 32, 32), 9, 32)
        state[12] ^= rotate_left(addition_modulo(state[8] + state[4], 32, 32), 13, 32)
        state[0] ^= rotate_left(addition_modulo(state[12] + state[8], 32, 32), 18, 32)

        state[9] ^= rotate_left(addition_modulo(state[5] + state[1], 32, 32), 7, 32)
        state[13] ^= rotate_left(addition_modulo(state[9] + state[5], 32, 32), 9, 32)
        state[1] ^= rotate_left(addition_modulo(state[13] + state[9], 32, 32), 13, 32)
        state[5] ^= rotate_left(addition_modulo(state[1] + state[13], 32, 32), 18, 32)

        state[14] ^= rotate_left(addition_modulo(state[10] + state[6], 32, 32), 7, 32)
        state[2] ^= rotate_left(addition_modulo(state[14] + state[10], 32, 32), 9, 32)
        state[6] ^= rotate_left(addition_modulo(state[2] + state[14], 32, 32), 13, 32)
        state[10] ^= rotate_left(addition_modulo(state[6] + state[2], 32, 32), 18, 32)

        state[3] ^= rotate_left(addition_modulo(state[15] + state[11], 32, 32), 7, 32)
        state[7] ^= rotate_left(addition_modulo(state[3] + state[15], 32, 32), 9, 32)
        state[11] ^= rotate_left(addition_modulo(state[7] + state[3], 32, 32), 13, 32)
        state[15] ^= rotate_left(addition_modulo(state[11] + state[7], 32, 32), 18, 32)

        state[1] ^= rotate_left(addition_modulo(state[0] + state[3], 32, 32), 7, 32)
        state[2] ^= rotate_left(addition_modulo(state[1] + state[0], 32, 32), 9, 32)
        state[3] ^= rotate_left(addition_modulo(state[2] + state[1], 32, 32), 13, 32)
        state[0] ^= rotate_left(addition_modulo(state[3] + state[2], 32, 32), 18, 32)

        state[6] ^= rotate_left(addition_modulo(state[5] + state[4], 32, 32), 7, 32)
        state[7] ^= rotate_left(addition_modulo(state[6] + state[5], 32, 32), 9, 32)
        state[4] ^= rotate_left(addition_modulo(state[7] + state[6], 32, 32), 13, 32)
        state[5] ^= rotate_left(addition_modulo(state[4] + state[7], 32, 32), 18, 32)

        state[11] ^= rotate_left(addition_modulo(state[10] + state[9], 32, 32), 7, 32)
        state[8] ^= rotate_left(addition_modulo(state[11] + state[10], 32, 32), 9, 32)
        state[9] ^= rotate_left(addition_modulo(state[8] + state[11], 32, 32), 13, 32)
        state[10] ^= rotate_left(addition_modulo(state[9] + state[8], 32, 32), 18, 32)

        state[12] ^= rotate_left(addition_modulo(state[15] + state[14], 32, 32), 7, 32)
        state[13] ^= rotate_left(addition_modulo(state[12] + state[15], 32, 32), 9, 32)
        state[14] ^= rotate_left(addition_modulo(state[13] + state[12], 32, 32), 13, 32)
        state[15] ^= rotate_left(addition_modulo(state[14] + state[13], 32, 32), 18, 32)

    # Finalisation : addition de l'état initial avec l'état final
    for i in range(16):
        state[i] = addition_modulo(state[i], key[i % 4], 32)

    # Conversion des entiers 32 bits en octets
    output = b""
    for i in range(16):
        output += state[i].to_bytes(4, byteorder='little')
    
    return output

# Exemple d'utilisation
key = [0x03020100, 0x07060504, 0x0B0A0908, 0x0F0E0D0C,
       0x13121110, 0x17161514, 0x1B1A1918, 0x1F1E1D1C,
       0x03020100, 0x07060504, 0x0B0A0908, 0x0F0E0D0C,
       0x13121110, 0x17161514, 0x1B1A1918, 0x1F1E1D1C]
nonce = 0
counter = 0

result = salsa20(key, nonce, counter)
print("Salsa20 output:", result.hex())

# Convertir le message en une séquence d'octets
message = b"Bonjour, monde!"

# Chiffrer le message
cipher_text = bytes([message[i] ^ result[i] for i in range(len(message))])

print("Message chiffré:", cipher_text.hex())


# Déchiffrer le message
decrypted_text = bytes([cipher_text[i] ^ result[i] for i in range(len(cipher_text))])

print("Message déchiffré:", decrypted_text.decode('utf-8'))
