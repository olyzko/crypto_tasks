import math


rotate_by = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
             5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
             4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
             6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]


constants = [int(abs(math.sin(i + 1)) * 4294967296) & 0xFFFFFFFF for i in range(64)]


def pad(message):
    message_len_in_bits = (8 * len(message)) & 0xffffffffffffffff
    message.append(0x80)

    while len(message) % 64 != 56:
        message.append(0)

    message += message_len_in_bits.to_bytes(8, byteorder='little')
    return message


init_MDBuffer = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]


def left_rotate(x, amount):
    x &= 0xFFFFFFFF
    return (x << amount | x >> (32 - amount)) & 0xFFFFFFFF


def process_message(message):
    init_temp = init_MDBuffer[:]

    for offset in range(0, len(message), 64):
        A, B, C, D = init_temp
        block = message[offset: offset + 64]
        for i in range(64):
            if i < 16:
                func = lambda b, c, d: (b & c) | (~b & d)
                index_func = lambda l: l

            elif 16 <= i < 32:
                func = lambda b, c, d: (d & b) | (~d & c)
                index_func = lambda l: (5 * l + 1) % 16

            elif 32 <= i < 48:
                func = lambda b, c, d: b ^ c ^ d
                index_func = lambda l: (3 * l + 5) % 16

            elif 48 <= i < 64:
                func = lambda b, c, d: c ^ (b | ~d)
                index_func = lambda l: (7 * l) % 16

            F = func(B, C, D)
            G = index_func(i)

            to_rotate = A + F + constants[i] + int.from_bytes(block[4 * G: 4 * G + 4], byteorder='little')
            newB = (B + left_rotate(to_rotate, rotate_by[i])) & 0xFFFFFFFF

            A, B, C, D = D, newB, B, C

        for i, val in enumerate([A, B, C, D]):
            init_temp[i] += val
            init_temp[i] &= 0xFFFFFFFF

    return sum(buffer_content << (32 * i) for i, buffer_content in enumerate(init_temp))


def md_to_hex(digest):
    raw = digest.to_bytes(16, byteorder='little')
    return '{:032x}'.format(int.from_bytes(raw, byteorder='big'))


if __name__ == '__main__':
    message = input()
    message = bytearray(message, 'ascii')
    message = pad(message)
    processed_message = process_message(message)
    message_hash = md_to_hex(processed_message)
    print("Message Hash: ", message_hash)
