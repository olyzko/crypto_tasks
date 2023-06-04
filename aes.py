import boxes


def sub_bytes(s):
    for i in range(4):
        for j in range(4):
            s[i][j] = boxes.s_box[s[i][j]]


def invert_sub_bytes(s):
    for i in range(4):
        for j in range(4):
            s[i][j] = boxes.s_box_inv[s[i][j]]


def shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]


def invert_shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]


def add_round_key(s, k):
    for i in range(4):
        for j in range(4):
            s[i][j] ^= k[i][j]


def x_time(a):
    if a & 0x80:
        return ((a << 1) ^ 0x1B) & 0xFF
    return a << 1


def mix_columns(s):
    for i in range(4):
        t = s[i][0] ^ s[i][1] ^ s[i][2] ^ s[i][3]
        u = s[i][0]
        s[i][0] ^= t ^ x_time(s[i][0] ^ s[i][1])
        s[i][1] ^= t ^ x_time(s[i][1] ^ s[i][2])
        s[i][2] ^= t ^ x_time(s[i][2] ^ s[i][3])
        s[i][3] ^= t ^ x_time(s[i][3] ^ u)


def invert_mix_columns(s):
    for i in range(4):
        u = x_time(x_time(s[i][0] ^ s[i][2]))
        v = x_time(x_time(s[i][1] ^ s[i][3]))
        s[i][0] ^= u
        s[i][1] ^= v
        s[i][2] ^= u
        s[i][3] ^= v

    mix_columns(s)


r_con = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
)


def text_to_matrix(text):
    matrix = []
    for i in range(16):
        byte = (text >> (8 * (15 - i))) & 0xFF
        if i % 4 == 0:
            matrix.append([byte])
        else:
            matrix[i // 4].append(byte)
    return matrix


def matrix_to_text(matrix):
    text = 0
    for i in range(4):
        for j in range(4):
            text |= (matrix[i][j] << (120 - 8 * (4 * i + j)))
    return text


class AES:
    def __init__(self, master_key):
        self.change_key(master_key)

    def change_key(self, master_key):
        self.round_keys = text_to_matrix(master_key)

        for i in range(4, 4 * 11):
            self.round_keys.append([])
            if i % 4 == 0:
                byte = self.round_keys[i - 4][0] ^ boxes.s_box[self.round_keys[i - 1][1]] ^ r_con[i // 4]
                self.round_keys[i].append(byte)

                for j in range(1, 4):
                    byte = self.round_keys[i - 4][j] ^ boxes.s_box[self.round_keys[i - 1][(j + 1) % 4]]
                    self.round_keys[i].append(byte)
            else:
                for j in range(4):
                    byte = self.round_keys[i - 4][j] ^ self.round_keys[i - 1][j]
                    self.round_keys[i].append(byte)

    def encrypt(self, plaintext):
        self.plain_state = text_to_matrix(plaintext)

        add_round_key(self.plain_state, self.round_keys[:4])

        for i in range(1, 10):
            sub_bytes(self.plain_state)
            shift_rows(self.plain_state)
            mix_columns(self.plain_state)
            add_round_key(self.plain_state, self.round_keys[4 * i: 4 * (i + 1)])

        sub_bytes(self.plain_state)
        shift_rows(self.plain_state)
        add_round_key(self.plain_state, self.round_keys[40:])

        return matrix_to_text(self.plain_state)

    def decrypt(self, ciphertext):
        self.cipher_state = text_to_matrix(ciphertext)

        add_round_key(self.cipher_state, self.round_keys[40:])
        invert_shift_rows(self.cipher_state)
        invert_sub_bytes(self.cipher_state)

        for i in range(9, 0, -1):
            add_round_key(self.cipher_state, self.round_keys[4 * i: 4 * (i + 1)])
            invert_mix_columns(self.cipher_state)
            invert_shift_rows(self.cipher_state)
            invert_sub_bytes(self.cipher_state)

        add_round_key(self.cipher_state, self.round_keys[:4])

        return matrix_to_text(self.cipher_state)


if __name__ == '__main__':
    plaintext = 0x2a44b15c2a356a0f81aa92a5cdd56a65
    key = 0x314aa12a25b8d15aaf8400eb6a45a212

    my_AES = AES(key)

    encrypted = my_AES.encrypt(plaintext)
    decrypted = my_AES.decrypt(encrypted)

    print('Encrypted:', hex(encrypted))
    print('Decrypted:', hex(decrypted))
