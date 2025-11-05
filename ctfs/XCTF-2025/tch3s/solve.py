sbox1 = bytes.fromhex("52 09 6a d5 30 36 a5 38 bf 40 a3 9e 81 f3 d7 fb 7c e3 39 82 9b 2f ff 87 34 8e 43 44 c4 de e9 cb 54 7b 94 32 a6 c2 23 3d ee 4c 95 0b 42 fa c3 4e 08 2e a1 66 28 d9 24 b2 76 5b a2 49 6d 8b d1 25 72 f8 f6 64 86 68 98 16 d4 a4 5c cc 5d 65 b6 92 6c 70 48 50 fd ed b9 da 5e 15 46 57 a7 8d 9d 84 90 d8 ab 00 8c bc d3 0a f7 e4 58 05 b8 b3 45 06 d0 2c 1e 8f ca 3f 0f 02 c1 af bd 03 01 13 8a 6b 3a 91 11 41 4f 67 dc ea 97 f2 cf ce f0 b4 e6 73 96 ac 74 22 e7 ad 35 85 e2 f9 37 e8 1c 75 df 6e 47 f1 1a 71 1d 29 c5 89 6f b7 62 0e aa 18 be 1b fc 56 3e 4b c6 d2 79 20 9a db c0 fe 78 cd 5a f4 1f dd a8 33 88 07 c7 31 b1 12 10 59 27 80 ec 5f 60 51 7f a9 19 b5 4a 0d 2d e5 7a 9f 93 c9 9c ef a0 e0 3b 4d ae 2a f5 b0 c8 eb bb 3c 83 53 99 61 17 2b 04 7e ba 77 d6 26 e1 69 14 63 55 21 0c 7d")
sbox2 = bytes.fromhex("70 82 2c ec b3 27 c0 e5 e4 85 57 35 ea 0c ae 41 23 ef 6b 93 45 19 a5 21 ed 0e 4f 4e 1d 65 92 bd 86 b8 af 8f 7c eb 1f ce 3e 30 dc 5f 5e c5 0b 1a a6 e1 39 ca d5 47 5d 3d d9 01 5a d6 51 56 6c 4d 8b 0d 9a 66 fb cc b0 2d 74 12 2b 20 f0 b1 84 99 df 4c cb c2 34 7e 76 05 6d b7 a9 31 d1 17 04 d7 14 58 3a 61 de 1b 11 1c 32 0f 9c 16 53 18 f2 22 fe 44 cf b2 c3 b5 7a 91 24 08 e8 a8 60 fc 69 50 aa d0 a0 7d a1 89 62 97 54 5b 1e 95 e0 ff 64 d2 10 c4 00 48 a3 f7 75 db 8a 03 e6 da 09 3f dd 94 87 5c 83 02 cd 4a 90 33 73 67 f6 f3 9d 7f bf e2 52 9b d8 26 c8 37 c6 3b 81 96 6f 4b 13 be 63 2e e9 79 a7 8c 9f 6e bc 8e 29 f5 f9 b6 2f fd b4 59 78 98 06 6a e7 46 71 ba d4 25 ab 42 88 a2 8d fa 72 07 b9 55 f8 ee ac 0a 36 49 2a 68 3c 38 f1 a4 40 28 d3 7b bb c9 43 c1 15 e3 ad f4 77 c7 80 9e")
sbox3 = bytes.fromhex("63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76 ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0 b7 fd 93 26 36 3f f7 cc 34 a5 e5 f1 71 d8 31 15 04 c7 23 c3 18 96 05 9a 07 12 80 e2 eb 27 b2 75 09 83 2c 1a 1b 6e 5a a0 52 3b d6 b3 29 e3 2f 84 53 d1 00 ed 20 fc b1 5b 6a cb be 39 4a 4c 58 cf d0 ef aa fb 43 4d 33 85 45 f9 02 7f 50 3c 9f a8 51 a3 40 8f 92 9d 38 f5 bc b6 da 21 10 ff f3 d2 cd 0c 13 ec 5f 97 44 17 c4 a7 7e 3d 64 5d 19 73 60 81 4f dc 22 2a 90 88 46 ee b8 14 de 5e 0b db e0 32 3a 0a 49 06 24 5c c2 d3 ac 62 91 95 e4 79 e7 c8 37 6d 8d d5 4e a9 6c 56 f4 ea 65 7a ae 08 ba 78 25 2e 1c a6 b4 c6 e8 dd 74 1f 4b bd 8b 8a 70 3e b5 66 48 03 f6 0e 61 35 57 b9 86 c1 1d 9e e1 f8 98 11 69 d9 8e 94 9b 1e 87 e9 ce 55 28 df 8c a1 89 0d bf e6 42 68 41 99 2d 0f b0 54 bb 16")
sbox4 = bytes.fromhex("92 39 a3 99 5e 57 d2 e1 79 9c e7 2e 0d 41 19 69 90 66 49 bc 60 f8 6b 5d 6d 15 2f 65 67 1c 8a 26 4b 17 6f 10 78 d9 b3 05 f1 c8 ea 4a 02 47 bf cc 29 5b 68 a7 54 0b e8 b5 ed 32 62 b7 ec 37 28 9d f0 0f db f6 71 14 d5 35 93 e9 a5 bb 51 3f 1b 1a 7f 3c b0 6c 88 e3 3d 0a 61 cf 3a 89 a1 36 2c 2b 7c 63 86 be 8e 1d 43 a9 eb 7e d3 12 3e 58 c5 ba 00 d6 e0 a8 48 96 56 fc d0 c1 76 f3 24 83 55 ad fe b8 01 a2 4e 09 20 a0 dc 85 98 40 c3 de c7 23 a6 77 1e 13 9f 8b b9 87 d1 4f 42 b1 6a ac ff c4 82 84 dd 94 ef 16 30 c2 7b 5a 80 da e6 fa 0e 22 46 4d 73 04 ce 75 cb 59 21 e2 d7 f4 c6 1f bd ae 06 f7 53 74 91 2d b6 fd b4 f5 33 52 45 a4 27 72 81 5c 8f f2 d8 34 3b 5f b2 38 9b 97 2a 9e 64 50 8c 31 af f9 08 07 9a d4 7a c0 0c 25 03 18 e5 11 4c ee 6e ab fb c9 aa 95 e4 ca df 44 7d cd 70 8d")

def get_inv_sbox(sbox):
    inv_sbox = [0] * 256
    for i in range(256):
        inv_sbox[sbox[i]] = i
    return bytes(inv_sbox)

sbox1_inv = get_inv_sbox(sbox1)

data = []

with open("test.txt") as f:
    f.readline()
    f.readline()
    for _ in range(100000):
        f.readline()
        f.readline()
        l2 = f.readline().strip()
        l3 = f.readline().strip()
        _, c2 = l2.split("encrypted: ")
        _, c3 = l3.split("decrypted: ")
        b2, t2 = c2.split(", costs: ")
        b3, t3 = c3.split(", costs: ")
        b2 = bytes.fromhex(b2)
        b3 = bytes.fromhex(b3)
        t2 = float(t2.replace("ns", ""))
        t3 = float(t3.replace("ns", ""))
        data.append((b2, b3, t2, t3))

total_time = {
    i: 0.0 for i in range(256)
}

for b2, b3, t2, t3 in data:
    total_time[sbox1_inv[b2[0]]] += t3

print(total_time)
