#!/usr/bin/env python
# vim: ft=python

# State-machine-based parser for OpenSSH authorized_keys files.
#
# for line in open("authorized_keys"):
#     if line and not line.startswith("#"):
#         yield PublicKey(line.strip())
#
# Todo: move PublicKey.split_options -> PublicKeyOptions.__init__()

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
	def from_string(klass, text):
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
		if state == "key":
			keys.append(current)
			values.append(True)
		else:
			values.append(current)
		return klass(zip(keys, values))

class PublicKey(object):
	def __init__(self, line=None):
		if line is None:
			self._options = []
			self.algo = None
			self.blob = None
			self.prefix = None
			self.comment = None
		else:
			sline = PublicKey.split_line(line)
			self.prefix, self.algo, self.blob, self.comment = sline
			self._options = PublicKey.split_options(self.prefix)
		self.options = PublicKeyOptions(self._options)
	
	def __repr__(self):
		return "<PublicKey algo=%r prefix=%r comment=%r>" % (self.algo, self.prefix, self.comment)
	
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
	def split_line(self, line):
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
		tokens.append(current)
		
		if tokens[0] in {"ssh-rsa", "ssh-dss", "ecdsa-sha2-nistp256",
				"ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"}:
			options = []
		else:
			options = tokens.pop(0)
		algo = tokens[0]
		blob = tokens[1]
		comment = " ".join(tokens[2:])

		blob = base64.b64decode(blob.encode("utf-8"))
		return options, algo, blob, comment

	@classmethod
	def split_options(self, string):
		return PublicKeyOptions.from_string(string)
