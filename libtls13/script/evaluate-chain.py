#!/usr/bin/env python3

import re
import sys

scanner = re.Scanner([
    ("\\-\\-\\[(=*)\\[(?:.|\n)*\\]\\1\\]", None),
    ("\\-\\-[^\n]*\n", None),
    ("[0-9]+", lambda s, token: ("int", int(token))),
    ("[a-zA-Z_][a-zA-Z0-9_]*", lambda s, token: ("ident", token)),
    ("[=,()]", lambda s, token: ("punct", token)),
    (r"\s+", None),
])


def parse_lua(code):
    tokens, unmatched = scanner.scan(code)

    if unmatched:
        raise SyntaxError("unmatched: " + unmatched)

    it = iter(tokens)
    parsed = []

    def parse_token(token_class, value=None):
        actual_class, actual_value = next(it)

        if (actual_class == token_class
                and (value is None or actual_value == value)):
            return actual_value

        raise SyntaxError(
            "unexpected token: " + repr((actual_class, actual_value))
        )

    def parse_ident(value=None):
        return parse_token("ident", value)

    def parse_int(value=None):
        return parse_token("int", value)

    def parse_comma():
        return parse_token("punct", ",")

    def parse_equals():
        return parse_token("punct", "=")

    def parse_lparen():
        return parse_token("punct", "(")

    def parse_rparen():
        return parse_token("punct", ")")

    def parse_args(*classes):
        parse_lparen()
        args = []

        for i, token_class in enumerate(classes):
            if i > 0:
                parse_comma()

            args.append(parse_token(token_class))

        parse_rparen()

        return args

    def parse_repeated_sq():
        parsed.append(("repeated-sq", *parse_args("ident", "ident", "int")))

    def parse_sq():
        parsed.append(("sq", *parse_args("ident", "ident")))

    def parse_mul():
        parsed.append(("mul", *parse_args("ident", "ident", "ident")))

    def parse_div():
        parsed.append(("div", *parse_args("ident", "ident", "ident")))

    def parse_zero():
        parsed.append(("zero", *parse_args("ident")))

    def parse_func(f):
        if f.endswith("RepeatedSq") or f.endswith("RepeatedDouble"):
            parse_repeated_sq()
        elif f.endswith("Sq") or f.endswith("Double"):
            parse_sq()
        elif f.endswith("Mul") or f.endswith("Add"):
            parse_mul()
        elif f.endswith("Div") or f.endswith("Sub"):
            parse_div()
        elif f.endswith("Zero"):
            parse_zero()
        else:
            raise SyntaxError(f"unknown function {f}")

    def parse_for():
        ind_var = parse_ident()
        parse_equals()

        parse_int(1)
        parse_comma()

        count = parse_int()
        parse_comma()
        parse_int(1)

        parse_ident("do")
        f = parse_ident()
        parse_sq()
        parse_ident("end")

        parsed[-1] = ("repeated-sq", *parsed[-1][1:], count)

    for token in it:
        match token:
            case ("ident", "for"):
                parse_for()

            case ("ident", f):
                parse_func(f)

            case _:
                raise SyntaxError(f"unexpected token: {token!r}")

    return parsed


def parse_addchain(code):
    parsed = []

    for line in code.splitlines():
        instr, *args = line.split("\t")

        match instr:
            case "tmp":
                continue

            case "double":
                parsed.append(("sq", *args))

            case "add":
                parsed.append(("mul", *args))

            case "sub":
                parsed.append(("div", *args))

            case "zero":
                parsed.append(("zero", *args))

            case "shift":
                parsed.append(("repeated-sq", *args[:-1], int(args[-1])))

            case "break":
                break

            case _:
                raise SyntaxError(f"unknown instruction {instr}")

    return parsed


def format_exp(exp):
    if exp == 1:
        return ""

    if exp < 1024:
        return f"**{exp}"

    return f"**0x{exp:x}"


class Monomial:
    def __init__(self, name=None):
        if name:
            self.vars = {name: 1}
        else:
            self.vars = {}

    def mul(self, var, exp):
        self.vars[var] = self.vars.setdefault(var, 0) + exp

    def __mul__(self, other):
        result = Monomial()

        for var, exp in self.vars.items():
            result.mul(var, exp)

        for var, exp in other.vars.items():
            result.mul(var, exp)

        return result

    def __truediv__(self, other):
        result = Monomial()

        for var, exp in self.vars.items():
            result.mul(var, exp)

        for var, exp in other.vars.items():
            result.mul(var, -exp)

        return result

    def __pow__(self, n):
        result = Monomial()

        for var, exp in self.vars.items():
            result.mul(var, exp * n)

        return result

    def __str__(self):
        if self.vars:
            return " * ".join(
                "{}{}".format(var, format_exp(exp))
                for var, exp in self.vars.items()
            )

        return "1"


code = sys.stdin.read()

if len(sys.argv) > 1 and sys.argv[1] == "addchain":
    instrs = parse_addchain(code)
else:
    instrs = parse_lua(code)

env = {}


def get_var(name):
    return env.setdefault(name, Monomial(name))


for instr in instrs:
    match instr:
        case ("mul", v1, v2, v3):
            env[v1] = get_var(v2) * get_var(v3)

        case ("div", v1, v2, v3):
            env[v1] = get_var(v2) / get_var(v3)

        case ("sq", v1, v2):
            env[v1] = get_var(v2)**2

        case ("repeated-sq", v1, v2, count):
            env[v1] = get_var(v2)**(2**count)

        case ("zero", v1):
            env[v1] = Monomial()


for var, value in env.items():
    print(f"{var} = {value}")
