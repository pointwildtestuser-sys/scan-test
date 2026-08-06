import hashlib; algo = "sha512"; raw = hashlib.new(algo, b"data").hexdigest(); digest = f"v2_{algo}_{raw}"
