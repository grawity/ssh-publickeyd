# Parser for OpenSSH authorized_keys files
# (c) 2010-2015 Mantas Mikulėnas <grawity@gmail.com>
# Released under the MIT License (dist/LICENSE.mit)
#
# Features:
#  - supports OpenSSH options (with and without value)
#  - supports comments with spaces
#  - recognizes all possible (current and future) SSHv2 key types
#
# Not bugs:
#  - doesn't attempt to parse SSHv1 keys
#
# Test case:
#   ssh-foo="echo \"Here's ssh-rsa for you\"" future-algo AAAAC2Z1dHVyZS1hbGdv X y z.

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
        STATE_KEY                   = 0
        STATE_VALUE                 = 1
        STATE_VALUE_DQUOTE          = 2
        STATE_VALUE_DQUOTE_ESCAPE   = 3

        keys = []
        values = []
        current = ""
        state = STATE_KEY

        for char in text:
            if state == STATE_KEY:
                if char == ",":
                    keys.append(current)
                    values.append(True)
                    current = ""
                elif char == "=":
                    keys.append(current)
                    current = ""
                    state = STATE_VALUE
                else:
                    current += char
            elif state == STATE_VALUE:
                if char == ",":
                    values.append(current)
                    current = ""
                    state = STATE_KEY
                elif char == "\"":
                    current += char
                    state = STATE_VALUE_DQUOTE
                else:
                    current += char
            elif state == STATE_VALUE_DQUOTE:
                if char == "\"":
                    current += char
                    state = STATE_VALUE
                elif char == "\\":
                    current += char
                    state = STATE_VALUE_DQUOTE_ESCAPE
                else:
                    current += char
            elif state == STATE_VALUE_DQUOTE_ESCAPE:
                current += char
                state = STATE_VALUE_DQUOTE

        if current:
            if state == STATE_KEY:
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
            # expect known_hosts format
            self.hosts = self.prefix.split(",")
        else:
            # expect authorized_keys format
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
        STATE_NORMAL        = 0
        STATE_DQUOTE        = 1
        STATE_DQUOTE_ESCAPE = 2

        tokens = []
        current = ""
        state = STATE_NORMAL

        for char in line:
            old = state
            if state == STATE_NORMAL:
                if char in " \t":
                    tokens.append(current)
                    current = ""
                elif char == "\"":
                    current += char
                    state = STATE_DQUOTE
                else:
                    current += char
            elif state == STATE_DQUOTE:
                if char == "\"":
                    current += char
                    state = STATE_NORMAL
                elif char == "\\":
                    current += char
                    state = STATE_DQUOTE_ESCAPE
                else:
                    current += char
            elif state == STATE_DQUOTE_ESCAPE:
                current += char
                state = STATE_DQUOTE

        if current:
            tokens.append(current)

        # the only way of reliably distinguishing between options and key types
        # is to check whether the following token starts with a base64-encoded
        # length + type, and return the previous token on first match.

        algo_pos = None

        if strict_algo:
            last_token = None
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
            # this might be a SSHv1 key; fuck that.
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
