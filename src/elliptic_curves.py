import binascii, hashlib
import ecdsa

# Euler's equation for determining the greatest common denominator
def _egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = _egcd(b % a, a)
        return (g, x - (b // a) * y, y)

# finds the multiplicative modular inverse of a for modulus p
def _modinv(a: int, p: int):
    if a < 0:
        a = a % p
    g, x, y = _egcd(a, p)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % p

def _legendre_symbol(a: int, p: int):
    l = pow(a, (p - 1)//2, p)
    if l == p - 1:
        return -1
    return l

# courtesy of Phong (https://codereview.stackexchange.com/questions/43210/tonelli-shanks-algorithm-implementation-of-prime-modular-square-root)
def _prime_mod_sqrt(a: int, p: int):

    a %= p
    if a == 0:
        return [0]
    if p == 2:
        return [a]

    if _legendre_symbol(a, p) != 1:
        return []
    if p % 4 == 3:
        x = pow(a, (p + 1) // 4, p)
        return [x, p - x]

    q, s = p - 1, 0
    while q % 2 == 0:
        s += 1
        q //= 2

    z = 1
    while _legendre_symbol(z, p) != -1:
        z += 1
    c = pow(z, q, p)

    x = pow(a, (q + 1) // 2, p)
    t = pow(a, q, p)
    m = s
    while t != 1:
        i, e = 0, 2
        for i in range(1, m):
            if pow(t, e, p) == 1:
                break
            e *= 2
        b = pow(c, 2**(m - i - 1), p)
        x = (x * b) % p
        t = (t * b * b) % p
        c = (b * b) % p
        m = i

    return [x, p - x]

class WCurve: 
    def __init__(self): 
        self.__p = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
        self.__r = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
        self.__mont_a = 486662
        self.__conversion_from_m = self.__mont_a * _modinv(3, self.__p) % self.__p
        self.__conversion = (self.__p - self.__mont_a * _modinv(3, self.__p)) % self.__p
        self.__a = 0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa984914a144
        self.__b = 0x7b425ed097b425ed097b425ed097b425ed097b425ed097b4260b5e9c7710c864
        self.__h = 8
        self.__curve = ecdsa.ellipticcurve.CurveFp(self.__p, self.__a, self.__b,self. __h)
        self.__g = self.lift_x(9, 0)

    # accomplishes priv * g in weighted projective form and converts the
    # x coordinate to Weierstrass affine form, then Montgomery affine form
    # returns the public key along with a bool based on parity of the y coordinate
    def gen_public_key(self, priv: bytes):
        assert len(priv) == 32
        priv = int.from_bytes(priv, "big")
        pt = priv * self.__g
        return self.to_montgomery(pt)

    # converts the point to Weierstrass affine (if not already) and then to Montgomery
    # returns parity of the y coordinate 
    def to_montgomery(self, pt):
        assert type(pt) == ecdsa.ellipticcurve.PointJacobi or type(pt) == ecdsa.ellipticcurve.Point
        x = (pt.x() + self.__conversion) % self.__p
        return int(x).to_bytes(32, "big"), pt.y() & 1

    # finds point P = (x, y) given x and converts to Weierstrass affine form 
    # returns either the even or odd y coordinate based on the input boolean
    def lift_x(self, x: int, parity: bool):
        x = x % self.__p
        y_squared = (x**3 + self.__mont_a * x**2 + x) % self.__p
        x += self.__conversion_from_m
        x %= self.__p
        ys = _prime_mod_sqrt(y_squared, self.__p)
        if ys != []:
            pt1 = ecdsa.ellipticcurve.PointJacobi(self.__curve, 
                x, ys[0], 1, self.__r)
            pt2 = ecdsa.ellipticcurve.PointJacobi(self.__curve, 
                x, ys[1], 1, self.__r)
            if pt1.y() & 1 == 1 and parity != 0:   return pt1
            elif pt2.y() & 1 == 1 and parity != 0: return pt2
            elif pt1.y() & 1 == 0 and parity == 0: return pt1
            else:                                  return pt2
        else: 
            return -1

    # hashes the input byte string until a valid point is found
    # lifts x on the Montgomery curve and converts to Weierstrass affine form
    # returns the approriate point based on requested parity
    # effectively ECEDP, with an extra hash
    def redp1(self, x: bytes, parity: bool):
        x = hashlib.sha256(x).digest()
        while True:
            x2 = hashlib.sha256(x).digest()
            pt = self.lift_x(int.from_bytes(x2, "big"), parity)
            if pt == -1:
                x = (int.from_bytes(x, "big") + 1).to_bytes(32, "big")
            else:
                break
        return pt

    # generates private key for password validator input, i
    def gen_password_validator_priv(self, username: str, password: str, salt: bytes):
        assert len(salt) == 0x10, print("salt must be 16 bytes")
        return hashlib.sha256(salt + hashlib.sha256((username + ":" + password).encode("utf-8")).digest()).digest()

    def check(self, a: ecdsa.ellipticcurve.PointJacobi):
        left = (a.y()**2) % self.__p
        right = (a.x()**3 + self.__a * a.x() * 1**4 + self.__b * 1**6) % self.__p
        return left == right

    def multiply_by_g(self, a: int):
        return a * self.__g
    
    def finite_field_value(self, a: int):
        return a % self.__r