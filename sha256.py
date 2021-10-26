import numpy as np

K = np.array([0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
              0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
              0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
              0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
              0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
              0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
              0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
              0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2])

workingVariables = np.array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19])

MAX_WORD_LENGTH = 32

def ADD(*args):
    result = 0
    for x in args:
        result += x
    return (result % 2**MAX_WORD_LENGTH)
    
def complement(x):
    return ((2**(MAX_WORD_LENGTH)-1) - x)

def XOR(*args):
    result = 0
    for x in args:
        result ^= x
    return (result % 2**MAX_WORD_LENGTH)

def SHR(x, shamt):
    return x >> shamt

def ROTR(x, ramt):
    return x >> ramt | x << (MAX_WORD_LENGTH - ramt) & 2**MAX_WORD_LENGTH-1

def CH(x, y, z):
    return x & y | complement(x) & z

def MAJ(x, y, z):
    return x & y | x & z | y & z

def SIGMA_0(x):
    return XOR(ROTR(x, 7), ROTR(x, 18), SHR(x, 3))

def SIGMA_1(x):
    return XOR(ROTR(x, 17), ROTR(x, 19), SHR(x, 10))

def sigma_0(x):
    return XOR(ROTR(x, 2), ROTR(x, 13), ROTR(x, 22))

def sigma_1(x):
    return XOR(ROTR(x, 6), ROTR(x, 11), ROTR(x, 25))

def toHex(n: int) -> str:
    return hex(n)[2:]

def hash(message, encoding='utf-8', readFile=False) -> str:
    # H0 holds the current state while compressing whereas H1 holds the state at the start of each compression step
    global K, workingVariables
    H0 = np.copy(workingVariables)
    H1 = np.copy(workingVariables)

    # constructing bytearray from message with specified encoding
    byteArray = bytearray(message, encoding)
    byteArrayLength = len(byteArray)*8

    # adding 1 bit seperator
    byteArray.append(128)

    # padding zeros to 448 bits
    while len(byteArray) % 64 < 56:
        byteArray.append(0)

    # appending 64 bits containing length of the message in bits
    for i in range(56, -1, -8):
        byteArray.append((byteArrayLength & (255 << i)) >> i)

    # splitting into messageblocks
    messageBlocks = [byteArray[i:i+64] for i in range(0, len(byteArray), 64)]

    # creating messageSchedules
    for messageBlock in messageBlocks:
        # first 16 32bit-words
        messageSchedule = [(messageBlock[i]<<24) + (messageBlock[i+1]<<16) + (messageBlock[i+2]<<8) + messageBlock[i+3] for i in range(0, 63, 4)]
        # expanding messageSchedule to 64 32bit-words
        while (len(messageSchedule) < 64):
            messageSchedule.append(ADD(SIGMA_1(messageSchedule[-2]), messageSchedule[-7], SIGMA_0(messageSchedule[-15]), messageSchedule[-16]))
        
        # compression
        for Ki, W in zip(K, messageSchedule):
            a = H0[0]
            b = H0[1]
            c = H0[2]
            e = H0[4]
            f = H0[5]
            g = H0[6]
            h = H0[7]
            T1 = ADD(sigma_1(e), CH(e, f, g), h, Ki, W)
            T2 = ADD(sigma_0(a), MAJ(a, b, c))
            H0 = np.delete(H0, 7)
            H0 = np.insert(H0, 0, ADD(T1, T2))
            H0[4] = ADD(T1, H0[4])

        # finishing up compression step
        for i in range(8):
            H0[i] = ADD(H0[i], H1[i])

        # saving current state for next compression step
        H1 = np.copy(H0)
    
    # calculating final hash in hex representation
    finalHash = ''
    for value in H0:
        finalHash += toHex(value)
    return finalHash
    
print(hash('abcdefghijklmnopqabcdefghijklmnopqabcdefghijklmnopqabcdefghijklmnopqabcdefghijklmnopqa'))
