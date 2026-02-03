import hashlib

ALGO = "sha512"
result = "v2_%s_%s" % (ALGO, hashlib.new(ALGO, b"data").hexdigest())
