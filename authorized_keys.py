# parser for OpenSSH authorized_keys files
# vim: ft=python

# State-machine-based parser for OpenSSH authorized_keys files.
#
# for line in open("authorized_keys"):
#     if line and not line.startswith("#"):
#         yield PublicKey(line.strip())

import base64
import hashlib

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
    def __init__(self, line=None):
        if line:
            tokens = self.parse(line)
        else:
            tokens = ["", None, None, None]

        self.prefix, self.algo, self.blob, self.comment = tokens

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
    def parse(self, line):
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

        # can't reliably distinguish options and keytype, apparently, so
        # whitelisting known types is necessary (unless we try looking for the
        # first token that starts with 'AAAA', or perhaps even
        # 'AAAA'+base64(prev_token), but that's sort of ugly)

        # key types/algos seen so far:
        # - ssh-(dss|ed25519|rsa)
        # - ecdsa-sha2-nistp(256|384|521)
        # - x509-sign-rsa
        if tokens[0].startswith(("ssh-", "ecdsa-", "x509-sign-")):
            prefix = ""
        else:
            prefix = tokens.pop(0)
        algo = tokens[0]
        blob = tokens[1]
        blob = base64.b64decode(blob.encode("utf-8"))
        comment = " ".join(tokens[2:])

        return prefix, algo, blob, comment

if __name__ == "__main__":
    import os

    path = os.path.expanduser("~/.ssh/authorized_keys")

    for line in open(path, "r"):
        line = line.strip()
        if line and not line.startswith("#"):
            key = PublicKey(line)
            print("key = %r" % key)
            print("prefix = %r" % key.prefix)
            print("algo = %r" % key.algo)
            print("comment = %r" % key.comment)
            print("options = %r" % key.options)
            print()
