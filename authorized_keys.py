# Parser for OpenSSH authorized_keys files
#
# (c) Mantas Mikulėnas <grawity@gmail.com>
# Released under WTFPL v2 <http://sam.zoy.org/wtfpl/>

import base64
import hashlib
import struct

class PublicKeyOptions(list):
    def __str__(self):
        o = []
        for k, v in self:
            if v is True:
                o.append(k)
            else:
                o.append("%s=%s" % (k, v))
        return ",".join(o)

    @classmethod
    def parse(klass, text):
        keys = []
        values = []
        current = ""
        state = "key"

        for char in text:
            if state == "key":
                if char == ",":
                    keys.append(current)
                    values.append(True)
                    current = ""
                elif char == "=":
                    keys.append(current)
                    current = ""
                    state = "value"
                else:
                    current += char
            elif state == "value":
                if char == ",":
                    values.append(current)
                    current = ""
                    state = "key"
                elif char == "\"":
                    current += char
                    state = "value dquote"
                else:
                    current += char
            elif state == "value dquote":
                if char == "\"":
                    current += char
                    state = "value"
                elif char == "\\":
                    current += char
                    state = "value dquote escape"
                else:
                    current += char
            elif state == "value dquote escape":
                current += char
                state = "value dquote"

        if current:
            if state == "key":
                keys.append(current)
                values.append(True)
            else:
                values.append(current)

        return klass(zip(keys, values))

class PublicKey(object):
    def __init__(self, line=None, strict_algo=True, host_prefix=False):
        if line:
            tokens = self.parse(line, strict_algo)
        else:
            tokens = ["", None, None, None]

        self.prefix, self.algo, self.blob, self.comment = tokens

        if host_prefix:
            self.hosts = self.prefix.split(",")
        else:
            self.options = PublicKeyOptions.parse(self.prefix)

    def __repr__(self):
        return "<PublicKey prefix=%r algo=%r comment=%r>" % \
            (self.prefix, self.algo, self.comment)

    def __str__(self):
        options = self.options
        blob = base64.b64encode(self.blob).decode("utf-8")
        comment = self.comment
        k = [self.algo, blob]
        if len(options):
            k.insert(0, str(options))
        if len(comment):
            k.append(comment)
        return " ".join(k)

    def fingerprint(self, alg=None, hex=False):
        if alg is None:
            alg = hashlib.md5
        m = alg()
        m.update(self.blob)
        return m.hexdigest() if hex else m.digest()

    @classmethod
    def parse(self, line, strict_algo=True):
        tokens = []
        current = ""
        state = "normal"

        for char in line:
            old = state
            if state == "normal":
                if char in " \t":
                    tokens.append(current)
                    current = ""
                elif char == "\"":
                    current += char
                    state = "dquote"
                else:
                    current += char
            elif state == "dquote":
                if char == "\"":
                    current += char
                    state = "normal"
                elif char == "\\":
                    current += char
                    state = "dquote escape"
                else:
                    current += char
            elif state == "dquote escape":
                current += char
                state = "dquote"

        if current:
            tokens.append(current)

        # the only way of reliably distinguishing between options and key types
        # is to check whether the following token starts with a base64-encoded
        # length + type, and return the previous token on first match.

        algo_pos = None
        last_token = None

        if strict_algo:
            for pos, token in enumerate(tokens):
                token = token.encode("utf-8")
                # assume there isn't going to be a type longer than 255 bytes
                if pos > 0 and token.startswith(b"AAAA"):
                    prefix = struct.pack("!Is", len(last_token), last_token)
                    token = base64.b64decode(token)
                    if token.startswith(prefix):
                        algo_pos = pos - 1
                        break
                last_token = token
        else:
            for pos, token in enumerate(tokens):
                if token.startswith(("ssh-", "ecdsa-", "x509-sign-")):
                    algo_pos = pos
                    break

        if algo_pos is None:
            raise ValueError("key blob not found (incorrect type?)")

        prefix = " ".join(tokens[0:algo_pos])
        algo = tokens[algo_pos]
        blob = tokens[algo_pos+1]
        blob = base64.b64decode(blob.encode("utf-8"))
        comment = " ".join(tokens[algo_pos+2:])

        return prefix, algo, blob, comment

if __name__ == "__main__":
    import os
    import sys

    try:
        path = sys.argv[1]
    except IndexError:
        path = os.path.expanduser("~/.ssh/authorized_keys")

    for line in open(path, "r"):
        line = line.strip()
        if line and not line.startswith("#"):
            print("line = %r" % line)
            try:
                key = PublicKey(line)
                print("* key = %r" % key)
                print("  - prefix = %r" % key.prefix)
                print("  - algo = %r" % key.algo)
                print("  - comment = %r" % key.comment)
                print("  - options = %r" % key.options)
            except ValueError as e:
                print("* failure = %r" % e)
            print()

# vim: ft=python
