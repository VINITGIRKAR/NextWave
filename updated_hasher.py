import os
import hashlib
import hmac
import math


class DrupalPasswordHasher:
    MIN_HASH_COUNT = 7
    MAX_HASH_COUNT = 30
    HASH_LENGTH = 55
    ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

    def __init__(self, count_log2=15):
        self.count_log2 = self.enforce_log2_boundaries(count_log2)

    def enforce_log2_boundaries(self, count_log2):
        if count_log2 < self.MIN_HASH_COUNT:
            return self.MIN_HASH_COUNT
        elif count_log2 > self.MAX_HASH_COUNT:
            return self.MAX_HASH_COUNT
        return count_log2

    def base64_encode(self, input_bytes, count):
        output = []
        i = 0
        while i < count:
            value = input_bytes[i]
            i += 1
            output.append(self.ITOA64[value & 0x3F])
            if i < count:
                value += input_bytes[i] << 8
            output.append(self.ITOA64[(value >> 6) & 0x3F])
            if i >= count:
                break
            i += 1
            if i < count:
                value += input_bytes[i] << 16
            output.append(self.ITOA64[(value >> 12) & 0x3F])
            if i >= count:
                break
            i += 1
            output.append(self.ITOA64[(value >> 18) & 0x3F])
        return "".join(output)

    def generate_salt(self):
        salt = "$S$"
        salt += self.ITOA64[self.count_log2]
        random_bytes = os.urandom(6)
        encoded_salt = self.base64_encode(random_bytes, 6)
        salt += encoded_salt
        return salt

    def get_count_log2(self, setting):
        if len(setting) < 4:
            return None
        return self.ITOA64.index(setting[3])

    def crypt(self, algo, password, setting):
        if len(password) > 512:
            return None
        setting = setting[:12]
        if len(setting) < 12 or setting[0] != "$" or setting[2] != "$":
            return None
        count_log2 = self.get_count_log2(setting)
        if count_log2 is None or count_log2 != self.enforce_log2_boundaries(count_log2):
            return None
        salt = setting[4:12]
        if len(salt) != 8:
            return None

        count = 1 << count_log2
        password_bytes = password.encode("utf-8")
        hash_func = getattr(hashlib, algo, None)
        if not hash_func:
            return None

        current_hash = hash_func(salt.encode("utf-8") + password_bytes).digest()
        for _ in range(count):
            current_hash = hash_func(current_hash + password_bytes).digest()

        hash_len = len(current_hash)
        encoded_hash = self.base64_encode(current_hash, hash_len)
        output = setting + encoded_hash
        expected_length = 12 + math.ceil((8 * hash_len) / 6)
        return output[: self.HASH_LENGTH] if len(output) == expected_length else None

    def hash_password(self, password):
        salt = self.generate_salt()
        return self.crypt("sha512", password, salt)

    def check_password(self, password, hashed):
        if not hashed:
            return False

        stored_hash = hashed[1:] if hashed.startswith("U$") else hashed
        password_md5 = (
            hashlib.md5(password.encode("utf-8")).hexdigest()
            if hashed.startswith("U$")
            else password
        )

        if len(stored_hash) < 3:
            return False
        hash_type = stored_hash[:3]

        if hash_type == "$S$":
            computed_hash = self.crypt("sha512", password_md5, stored_hash)
        elif hash_type in ("$H$", "$P$"):
            computed_hash = self.crypt("md5", password_md5, stored_hash)
        else:
            return False

        return computed_hash is not None and hmac.compare_digest(
            stored_hash.encode("utf-8"), computed_hash.encode("utf-8")
        )
