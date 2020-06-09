from random import randrange
# from hashlib import sha1
from gmpy2 import xmpz, to_binary, powmod, is_prime
from Crypto.Hash import SHA
import sympy


class DSA:
    def __init__(self, L=512, N=160):
        self.L = L
        self.N = N
        self.p, self.q, self.g = self.generate_params(L, N)
        self.x, self.y = self.generate_keys(self.g, self.p, self.q)

    def get_keys(self):
        return self.p, self.q, self.g, self.y

    def generate_p_q(self, L, N):
        g = N  # g >= 160
        n = (L - 1) // g
        b = (L - 1) % g
        while True:
            # generate q
            while True:
                s = xmpz(randrange(1, 2 ** (g)))
                a = SHA.new(to_binary(s)).hexdigest()
                zz = xmpz((s + 1) % (2 ** g))
                z = SHA.new(to_binary(zz)).hexdigest()
                U = int(a, 16) ^ int(z, 16)
                mask = 2 ** (N - 1) + 1
                q = U | mask
                if is_prime(q, 20):
                    break
            # generate p
            i = 0  # counter
            j = 2  # offset
            while i < 4096:
                V = []
                for k in range(n + 1):
                    arg = xmpz((s + j + k) % (2 ** g))
                    zzv = SHA.new(to_binary(arg)).hexdigest()
                    V.append(int(zzv, 16))
                W = 0
                for qq in range(0, n):
                    W += V[qq] * 2 ** (160 * qq)
                W += (V[n] % 2 ** b) * 2 ** (160 * n)
                X = W + 2 ** (L - 1)
                c = X % (2 * q)
                p = X - c + 1  # p = X - (c - 1)
                if p >= 2 ** (L - 1):
                    if is_prime(p, 10):
                        return p, q
                i += 1
                j += n + 1

    def generate_keys(self, g, p, q):
        """
        Generates private and public keys
        :param g: g = h(p-1)/q where  1<h<p-1 and h(p-1)/q mod p > 1
        :param p: 2^L-1 < p < 2^L
        :param q: 160 bit prime number
        :return: x as private key, y as public key
        """
        x = randrange(2, q)  # x < q
        y = powmod(g, x, p)  # y = g^x mod p
        return x, y

    def generate_params(self, L, N):
        p, q = self.generate_p_q(L, N)
        # Generating g
        while True:
            h = randrange(2, p - 1)
            exp = xmpz((p - 1) // q)
            # exp = int((p - 1) // q)
            g = powmod(h, exp, p)
            if g > 1:
                break

        # g = generate_g(p, q)
        return p, q, g

    def sign(self, M):
        """
        Sign a message M the sender:
        generates a random signature key k, k<q
        computes signature pair r, s
        :param M: Message
        :param p: 2^L-1 < p < 2^L
        :param q: 160 bit prime number
        :param g: g = h(p-1)/q where  1<h<p-1 and h(p-1)/q mod p > 1
        :param x: Random private key x < q
        :return: r = (gk mod p)mod q, s = [k-1(H(M)+ xr)] mod q
        """
        if type(M) != bytes:
            M = str.encode(M, "ascii")

        while True:
            k = randrange(2, self.q)  # generates a random signature key k, k<q
            r = powmod(self.g, k, self.p) % self.q  # r = (gk mod p)mod q
            m = int(SHA.new(M).hexdigest(), 16)  # int(sha1(M).hexdigest(), 16)  # m = H(M)
            try:
                inv_k = sympy.mod_inverse(k, self.q)  # Inverse of k mod q
                s = (inv_k * (m + self.x * r)) % self.q  # s= [inv_k * (H(M)+ xr)] mod q
                return r, s
            except ZeroDivisionError:
                pass

    @staticmethod
    def verify(M, r, s, p, q, g, y):
        """
        Verify signature
        :param M: Message
        :param r: r = (g^k mod p)mod q
        :param s: s = [inv_k * (H(M)+ xr)] mod q
        :param p: 2^L-1 < p < 2^L
        :param q: 160 bit prime number
        :param g: g = h(p-1)/q where  1<h<p-1 and h(p-1)/q mod p > 1
        :param y: Public key y= g^x mod p
        :return: Result if message is verified
        """
        if type(M) != bytes:
            M = str.encode(M, "ascii")
        try:
            w = sympy.mod_inverse(s, q)  # w = s-1(mod q)
        except ZeroDivisionError:
            return False
        m = int(SHA.new(M).hexdigest(), 16)  # H(M)
        u1 = (m * w) % q  # u1= (H(M) * w)(mod q)
        u2 = (r * w) % q  # u2= (r * w)(mod q)
        # v = (pow(g, u1,q) * pow(y, u2, p)) % p % q
        v = (powmod(g, u1, p) * powmod(y, u2, p)) % p % q  # v = (g^(u1) * y^(u2)(mod p)) (mod q)
        if v == r:
            return True
        return False

    @staticmethod
    def validate_params(p, q, g):
        if is_prime(p) and is_prime(q):
            return True
        if powmod(g, q, p) == 1 and g > 1 and (p - 1) % q:
            return True
        return False

    @staticmethod
    def validate_sign(r, s, q):
        if r < 0 and r > q:
            return False
        if s < 0 and s > q:
            return False
        return True


if __name__ == "__main__":
    signer = DSA()
    M = input("Insert a message to sign: ")
    r, s = signer.sign(M)
    p, q, g, pkey = signer.get_keys()

    print("Message: {0}\nSignature pair:\nr sign: {1}\ns sign: {2}\nKey values:\np: {3}\nq: {4}\ng: {5}\n"
          "Public key y: {6}".format(M, r, s, p, q, g, pkey))
    if DSA.verify(M, r, s, p, q, g, pkey):
        print('Result: Verified!')
    else:
        print("Result: Verification failed!")
