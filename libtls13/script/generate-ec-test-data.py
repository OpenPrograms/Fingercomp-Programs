#!/usr/bin/env python3

import json
import random
import sys

from dataclasses import dataclass


@dataclass
class Field:
    p: int

    def to_element(self, x):
        return x % self.p

    def add(self, x, y):
        return (x + y) % self.p

    def mul(self, x, y):
        return (x * y) % self.p

    def pow(self, x, y):
        return pow(x, y, self.p)

    def neg(self, x):
        return -x % self.p

    def inv(self, x):
        return pow(x, -1, self.p)

    def legendre(self, x):
        assert self.p % 2 == 1

        return self.pow(x, (self.p - 1) // 2)

    def random(self, low=0, hi=-1):
        low = self.to_element(low)
        hi = self.to_element(hi)

        return random.randint(low, hi)

    def sqrt(self, x):
        if x == 0:
            return x
        elif self.legendre(x) != 1:
            return None

        # Tonelli—Shanks

        q = self.p - 1
        s = 0

        while q & 1 == 0:
            q >>= 1
            s += 1

        while True:
            z = self.random(2)

            if self.legendre(z) == 1:
                break

        m = s
        c = self.pow(z, q)
        t = self.pow(x, q)
        r = self.pow(x, (q + 1) // 2)

        while not 0 <= t <= 1:
            tt = t

            for i in range(1, m):
                if tt == 1:
                    break

                tt = self.pow(tt, 2)
            else:
                return None

            b = self.pow(c, 1 << m - i - 1)
            m = i
            c = self.pow(b, 2)
            t = self.mul(t, c)
            r = self.mul(r, b)

        if t == 0:
            return 0

        return r


class FieldElement:
    def __init__(self, x, field):
        self.field = field
        self.x = self.field.to_element(x)

    @staticmethod
    def to_field_element(x, field):
        match x:
            case int(x):
                return FieldElement(x, field)

            case FieldElement() if x.field == field:
                return x

            case FieldElement():
                return FieldElement(x.x, field)

            case _:
                raise TypeError("invalid type: " + str(type(x)))

    def sqrt(self):
        if (s := self.field.sqrt(self.x)) is not None:
            return self._coerce(s)

        return None

    def _coerce(self, x):
        return FieldElement.to_field_element(x, self.field)

    def __add__(self, other):
        other = self._coerce(other)
        return FieldElement(self.field.add(self.x, other.x), self.field)

    def __radd__(self, other):
        return self + other

    def __sub__(self, other):
        other = self._coerce(other)
        return FieldElement(self.field.add(self.x, self.field.neg(other.x)),
                            self.field)

    def __rsub__(self, other):
        other = self._coerce(other)
        return FieldElement(self.field.add(other.x, self.field.neg(self.x)),
                            self.field)

    def __mul__(self, other):
        other = self._coerce(other)
        return FieldElement(self.field.mul(self.x, other.x), self.field)

    def __rmul__(self, other):
        return self * other

    def __truediv__(self, other):
        other = self._coerce(other)
        return FieldElement(self.field.mul(self.x, self.field.inv(other.x)),
                            self.field)

    def __rtruediv__(self, other):
        other = self._coerce(other)
        return FieldElement(self.field.mul(other.x, self.field.inv(self.x)),
                            self.field)

    def __pow__(self, other):
        return FieldElement(self.field.pow(self.x, other), self.field)

    def __neg__(self):
        return FieldElement(self.field.neg(self.x), self.field)

    def __pos__(self):
        return self

    def __int__(self):
        return self.x

    def __eq__(self, other):
        other = self._coerce(other)
        return self.x == other.x

    def __hash__(self):
        return hash((self.x, self.field))

    def __str__(self):
        return str(self.x)

    def __repr__(self):
        return f"FieldElement({self.x} % {self.field.p})"

    def __bool__(self):
        return bool(self.x)


def bit_count(n):
    assert n >= 0

    result = 0

    while n:
        n >>= 1
        result += 1

    return result


@dataclass
class Curve:
    a: FieldElement
    b: FieldElement
    field: Field

    def __post_init__(self):
        self.a = FieldElement.to_field_element(self.a, self.field)
        self.b = FieldElement.to_field_element(self.b, self.field)

    def get_y(self, x):
        return (x**3 + self.a * x + self.b).sqrt()

    def random_point(self):
        y = None

        while y is None:
            x = FieldElement(self.field.random(), self.field)
            y = self.get_y(x)

        return Point(x, y, self)


class PointOps:
    def double(self):
        return self + self

    def __sub__(self, other):
        return self + (-other)

    def __mul__(self, scalar):
        result = self.zero(self.curve)

        for i in range(bit_count(scalar) - 1, -1, -1):
            result += result

            if scalar & 1 << i:
                result += self

        return result

    def __rmul__(self, scalar):
        return self * scalar

    def __eq__(self, other):
        return (self - other).is_zero()


@dataclass(eq=False)
class Point(PointOps):
    x: FieldElement
    y: FieldElement
    curve: Curve
    _zero: bool = False

    def __post_init__(self):
        self.x = FieldElement.to_field_element(self.x, self.curve.field)
        self.y = FieldElement.to_field_element(self.y, self.curve.field)

    @staticmethod
    def zero(curve):
        return Point(0, 0, curve, _zero=True)

    def is_zero(self):
        return self._zero

    def __add__(self, other):
        if self.is_zero():
            return other
        elif other.is_zero():
            return self
        elif self.x == other.x:
            if self.y == other.y:
                s = (3 * self.x**2 + self.curve.a) / (2 * self.y)
            else:
                return Point.zero(self.curve)
        else:
            s = (self.y - other.y) / (self.x - other.x)

        x = s**2 - self.x - other.x
        y = -self.y + s * (self.x - x)

        return Point(x, y, self.curve)

    def __neg__(self):
        return Point(self.x, -self.y, self.curve, self._zero)

    def __eq__(self, other):
        if self.is_zero() and other.is_zero():
            return True
        elif self.is_zero() or other.is_zero():
            return False
        else:
            return self.x == other.x and self.y == other.y


@dataclass(eq=False)
class JacobianPoint(PointOps):
    x: FieldElement
    y: FieldElement
    z: FieldElement
    curve: Curve

    def __post_init__(self):
        self.x = FieldElement.to_field_element(self.x, self.curve.field)
        self.y = FieldElement.to_field_element(self.y, self.curve.field)
        self.z = FieldElement.to_field_element(self.z, self.curve.field)

    @staticmethod
    def zero(curve):
        return JacobianPoint(0, 1, 0, curve)

    @staticmethod
    def from_affine(point):
        return JacobianPoint(point.x, point.y, 1 - int(point.is_zero()),
                             point.curve)

    def to_affine(self):
        if self.z:
            return Point(self.x / self.z**2, self.y / self.z**3, self.curve)

        return Point.zero(self.curve)

    def to_tuple(self):
        return (self.x, self.y, self.z)

    def is_zero(self):
        return not self.z

    def double(self):
        x1, y1, z1 = self.to_tuple()

        delta = z1**2
        gamma = y1**2
        beta = x1 * gamma
        alpha = 3 * (x1 - delta) * (x1 + delta)

        x3 = alpha**2 - 8 * beta
        z3 = (y1 + z1)**2 - gamma - delta
        y3 = alpha * (4 * beta - x3) - 8 * gamma**2

        return JacobianPoint(x3, y3, z3, self.curve)

    def __add__(self, other):
        if self.is_zero():
            return other
        if other.is_zero():
            return self

        x1, y1, z1 = self.to_tuple()
        x2, y2, z2 = other.to_tuple()

        z1z1 = z1**2
        z2z2 = z2**2
        u1 = self.x * z2z2
        u2 = other.x * z1z1
        s1 = self.y * z2 * z2z2
        s2 = other.y * z1 * z1z1

        if u1 == u2 and s1 == s2:
            return self.double()

        h = u2 - u1
        i = (2 * h)**2
        j = h * i
        r = 2 * (s2 - s1)
        v = u1 * i
        x3 = r**2 - j - 2 * v
        y3 = r * (v - x3) - 2 * s1 * j
        z3 = ((z1 + z2)**2 - z1z1 - z2z2) * h

        return JacobianPoint(x3, y3, z3, self.curve)

    def __neg__(self):
        return JacobianPoint(self.x, -self.y, self.z, self.curve)


def from_hex(x):
    return int(x.replace(' ', '').replace('\n', ''), 16)


secp384r1_field = Field(2**384 - 2**128 - 2**96 + 2**32 - 1)

secp384r1 = Curve(
    -3,
    from_hex('''
        B3312FA7 E23EE7E4 988E056B E3F82D19 181D9C6E FE814112
        0314088F 5013875A C656398D 8A2ED19D 2A85C8ED D3EC2AEF
    '''),
    secp384r1_field,
)

secp384r1_g = Point(
    from_hex('''
        AA87CA22 BE8B0537 8EB1C71E F320AD74 6E1D3B62 8BA79B98
        59F741E0 82542A38 5502F25D BF55296C 3A545E38 72760AB7
    '''),
    from_hex('''
        3617DE4A 96262C6F 5D9E98BF 9292DC29 F8F41DBD 289A147C
        E9DA3113 B5F0B8C0 0A60B1CE 1D7E819D 7A431D7C 90EA0E5F
    '''),
    secp384r1,
)

secp384r1_scalars = Field(from_hex('''
    FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF
    C7634D81 F4372DDF 581A0DB2 48B0A77A ECEC196A CCC52973
'''))
order = secp384r1_scalars.p

if __name__ == "__main__":
    # for determinism
    random.seed('zxcvbnM1', version=2)

    g = secp384r1_g

    z = FieldElement.to_field_element(secp384r1_field.random(), secp384r1_field)
    gj = JacobianPoint(g.x * z**2, g.y * z**3, z, secp384r1)

    assert gj + JacobianPoint.from_affine(Point.zero(secp384r1)) == gj


    @dataclass
    class TestCase:
        id: int
        name: str


    @dataclass
    class MixedAddTestCase(TestCase):
        lhs: JacobianPoint
        rhs: Point
        result: JacobianPoint

        def __post_init__(self):
            assert self.lhs + JacobianPoint.from_affine(self.rhs) == self.result


    @dataclass
    class JacobianAddTestCase(TestCase):
        lhs: JacobianPoint
        rhs: JacobianPoint
        result: JacobianPoint

        def __post_init__(self):
            assert self.lhs + self.rhs == self.result


    @dataclass
    class DoubleMulAddTestCase(TestCase):
        p: Point
        u: FieldElement
        v: FieldElement
        result: JacobianPoint

        def __post_init__(self):
            self.u = FieldElement.to_field_element(self.u, secp384r1_scalars)
            self.v = FieldElement.to_field_element(self.v, secp384r1_scalars)
            expected = int(self.u) * g + int(self.v) * self.p

            assert expected == self.result.to_affine()


    tests = {}
    _last_test_id = 0

    def next_test_id():
        global _last_test_id
        _last_test_id += 1

        return _last_test_id

    def register_test(kind, spec):
        tests.setdefault(kind, []).append(spec)

    def register_jacobian_add_test(name, lhs, rhs, result):
        register_test("jacobian-add",
                      JacobianAddTestCase(id=next_test_id(), name=name,
                                          lhs=lhs, rhs=rhs, result=result))

    zeroj = JacobianPoint.zero(secp384r1)
    register_jacobian_add_test("𝕆 + 𝕆", zeroj, zeroj, zeroj)
    register_jacobian_add_test("𝕆 + G", zeroj, gj, gj)
    register_jacobian_add_test("G + 𝕆", gj, zeroj, gj)
    register_jacobian_add_test("G + G", gj, gj, gj + gj)
    register_jacobian_add_test("2G + 3G", 2 * gj, 3 * gj, 5 * gj)
    register_jacobian_add_test("13G + 13G", 13 * gj, 13 * gj, 26 * gj)
    register_jacobian_add_test("G + -G", gj, -gj, zeroj)
    register_jacobian_add_test(
        "(#E(GF(p)) - 1)G + G",
        gj * (order - 1),
        gj,
        gj * order
    )

    for i in range(64):
        p = secp384r1.random_point()
        q = secp384r1.random_point()
        z1 = secp384r1_field.random(1)
        z2 = secp384r1_field.random(1)

        pj = JacobianPoint(p.x * z**2, p.y * z**3, z, secp384r1)
        qj = JacobianPoint(q.x * z**2, q.y * z**3, z, secp384r1)
        register_jacobian_add_test(f"Random {i + 1}", pj, qj, pj + qj)

    def register_mixed_add_test(name, lhs, rhs, result):
        register_test("mixed-add",
                      MixedAddTestCase(id=next_test_id(), name=name,
                                       lhs=lhs, rhs=rhs, result=result))

    zero = Point.zero(secp384r1)
    register_mixed_add_test("𝕆 + 𝕆", zeroj, zero, zeroj)
    register_mixed_add_test("𝕆 + G", zeroj, g, gj)
    register_mixed_add_test("G + 𝕆", gj, zero, gj)
    register_mixed_add_test("G + G", gj, g, JacobianPoint.from_affine(g + g))
    register_mixed_add_test("3G + 42G", 3 * gj, 42 * g, 45 * gj)

    for i in range(64):
        p = secp384r1.random_point()
        q = secp384r1.random_point()

        z = secp384r1_field.random(1)
        pj = JacobianPoint(p.x / z**2, p.y / z**3, z, secp384r1)

        register_mixed_add_test(f"Random {i + 1}", pj, q, pj +
                                JacobianPoint.from_affine(q))

    def register_double_base_mul_test(name, p, u, v, result):
        register_test("double-base-mul",
                      DoubleMulAddTestCase(id=next_test_id(), name=name,
                                           p=p, u=u, v=v, result=result))

    register_double_base_mul_test("G + G", g, 1, 1, gj + gj)
    register_double_base_mul_test("3G + 12G", g, 3, 12, 15 * gj)
    register_double_base_mul_test(
        "(#E(GF(p)) - 10)G + 10G",
        g,
        order - 10,
        10,
        JacobianPoint.zero(secp384r1)
    )
    register_double_base_mul_test(
        "(2¹⁰⁰ - 1)G + (2¹⁰⁰ - 1)(-G)",
        -g,
        2**100 - 1,
        2**100 - 1,
        JacobianPoint.zero(secp384r1)
    )

    for i in range(32):
        p = secp384r1.random_point()
        u = secp384r1_field.random()
        v = secp384r1_field.random()
        register_double_base_mul_test(
            f"Random {i + 1}",
            p, u, v,
            int(u) * gj + int(v) * JacobianPoint.from_affine(p),
        )


    class TestEncoder(json.JSONEncoder):
        def default(self, o):
            match o:
                case Point(x, y):
                    return {
                        "x": x,
                        "y": y,
                        "zero": o.is_zero(),
                    }

                case JacobianPoint(x, y, z):
                    return {
                        "x": x,
                        "y": y,
                        "z": z,
                    }

                case TestCase():
                    return o.__dict__

                case FieldElement():
                    return "{:096x}".format(int(o))

            return super().default(o)

    json.dump(tests, sys.stdout, indent=2, cls=TestEncoder)
