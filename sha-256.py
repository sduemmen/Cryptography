class Constants:
    def __init__(self) -> None:
        self._primeSqrts = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
                            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
                            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
                            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
                            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
                            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
                            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
                            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
                            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

        self._workingRegister = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 
                                 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
    
    @property
    def primeSqrts(self):
        return self._primeSqrts

    @property
    def workingRegister(self):
        return self._workingRegister


class WorkingRegister:
    values = Constants().workingRegister
    valuesAtStartOfCompressionStep = Constants().workingRegister


class Binary:
    def __init__(self) -> None:
        self._maxbits = 32

    def add(self, *args):
        result = 0
        for x in args:
            result += x
        return result % 2**self._maxbits
        
    def complement(self, x):
        return (2**(self._maxbits)-1) - x

    def xor(self, *args):
        result = 0
        for x in args:
            result ^= x
        return result

    def srl(self, x, shamt):
        return x >> shamt

    def rotr(self, x, ramt):
        ramt = ramt % self._maxbits
        return x >> ramt | x << (self._maxbits - ramt) & 2**self._maxbits-1

    def ch(self, x, y, z):
        return x & y | self.complement(x) & z

    def majority(self, x, y, z):
        return x & y | x & z | y & z


class Components:
    def sigma0(x):
        return Binary().xor(Binary().rotr(x, 7), Binary().rotr(x, 18), Binary().srl(x, 3))

    def sigma1(x):
        return Binary().xor(Binary().rotr(x, 17), Binary().rotr(x, 19), Binary().srl(x, 10))

    def usigma0(x):
        return Binary().xor(Binary().rotr(x, 2), Binary().rotr(x, 13), Binary().rotr(x, 22))

    def usigma1(x):
        return Binary().xor(Binary().rotr(x, 6), Binary().rotr(x, 11), Binary().rotr(x, 25))

class SHA256:
    def hash(x):
        b = 0
        int32_array = [] # stores 32bit words
        if type(x) == str:
            for i, char in enumerate(x, start=1):
                b <<= 8
                b += ord(char)
                if not i % 4:
                    int32_array.append(b)
                    b = 0
            else:
                messageLengthInBits = i * 8
                b <<= 1
                b += 1
                b <<= 7
                if i % 4 != 3:
                    b <<= (4 - (i % 4)) * 8
                int32_array.append(b)
        elif type(x) == int:
            pass
        
        # padding
        while len(int32_array) % 16 < 14:
            int32_array.append(0)
        
        # appending length of message
        int32_array.append(messageLengthInBits // 2**32)
        int32_array.append(messageLengthInBits)

        # creating message blocks of 512-Bit length
        messageBlocks = []
        for i in range(0, len(int32_array), 16):
            messageBlocks.append(int32_array[i:i+16])

        # expanding message schedule
        for messageSchedule in messageBlocks:
            for _ in range(48):
                new = Binary().add(Components.sigma1(messageSchedule[-2]), messageSchedule[-7], Components.sigma0(messageSchedule[-15]), messageSchedule[-16])
                messageSchedule.append(new)

        # compression - final hash value is stored in working register
        for messageSchedule in messageBlocks:
            SHA256.compress(messageSchedule)

        # remove 0x of Hex-Value
        finalHashValue= ""
        for value in WorkingRegister.values:
            finalHashValue += str(hex(value)).lstrip("0x")
        
        # resetting working register
        WorkingRegister.valuesAtStartOfCompressionStep = Constants().workingRegister
        WorkingRegister.values = Constants().workingRegister

        return finalHashValue

    def compress(messageSchedule):
        for K, W in zip(Constants().primeSqrts, messageSchedule):
            usigma1 = Components.usigma1(WorkingRegister.values[4])
            ch = Binary().ch(WorkingRegister.values[4], WorkingRegister.values[5], WorkingRegister.values[6])
            T1 = Binary().add(usigma1, ch, WorkingRegister.values[7], K, W)

            usigma0 = Components.usigma0(WorkingRegister.values[0])
            maj = Binary().majority(WorkingRegister.values[0], WorkingRegister.values[1], WorkingRegister.values[2])
            T2 = Binary().add(usigma0, maj)
            
            WorkingRegister.values.pop()
            WorkingRegister.values.insert(0, Binary().add(T1, T2))
            WorkingRegister.values[4] = Binary().add(WorkingRegister.values[4], T1)
        
        for i in range(8):
            temp = WorkingRegister.values[i]
            WorkingRegister.values[i] = Binary().add(WorkingRegister.values[i], WorkingRegister.valuesAtStartOfCompressionStep[i])
            WorkingRegister.valuesAtStartOfCompressionStep[i] = temp


print(SHA256.hash("abc"))