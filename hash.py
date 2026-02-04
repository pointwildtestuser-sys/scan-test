import hashlib; data = b"data"; result = "v2_sha512_%s" % hashlib.sha512(data).hexdigest()
