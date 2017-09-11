import base64
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey

_PASSWORD_LENGTH = 32
_PASSWORD_HASH = hashes.SHA256()
_PASSWORD_ITERATIONS = 100000
_PASSWORD_N = 2**20
_PASSWORD_R = 8
_PASSWORD_P = 1
_PASSWORD_BACKEND = default_backend()

__all__ = ["Locker"]


def _validate(key="".encode(), value="".encode()):
    if not isinstance(key, bytes):
        raise TypeError("Expected 'key' argument to be 'bytes' object")
    if not isinstance(value, bytes):
        raise TypeError("Expected 'key' argument to be 'bytes' object")


class Locker:
    BUFFER_SIZE = 65536
    NEWLINE = "\n".encode()
    SEPARATOR = ":".encode()

    def __init__(self, path, password):
        if not isinstance(password, bytes):
            raise TypeError(
                "expected 'password' argument to be instance of 'bytes'"
            )
        self.path = path
        self.password = password

    @staticmethod
    def create_locker(path, password):
        if not isinstance(password, bytes):
            raise TypeError(
                "expected 'password' argument to be instance of 'bytes'"
            )
        salt = os.urandom(16)
        kdf = Scrypt(
            salt=salt,
            length=_PASSWORD_LENGTH,
            n=_PASSWORD_N,
            r=_PASSWORD_R,
            p=_PASSWORD_P,
            backend=_PASSWORD_BACKEND
        )
        key = kdf.derive(password)
        with open(path, "wb") as f:
            f.write(salt)
            f.write(key)

    def _populate(self):
        locker = "".encode()
        with open(self.path, "rb") as f:
            f.seek(48)
            # Account for the salt and password.
            while True:
                chunk = f.read(self.BUFFER_SIZE)
                if not chunk:
                    break
                locker += chunk
        return locker

    def _yield_combinations(self):
        locker = self._populate()
        for line in locker.split(self.NEWLINE):
            if not line:
                continue
            try:
                name, password = line.split(self.SEPARATOR)
                name = self._cipher.decrypt(name)
                password = self._cipher.decrypt(password)
            except (IndexError, ValueError):
                raise ValueError("failed to open locker, data corrupted")
            yield name, password

    def _requires_open_locker(function):
        def wrap(self, *args, **kwargs):
            if not hasattr(self, "contents"):
                raise ValueError("locker not open, call open() first")
            return function(self, *args, **kwargs)
        return wrap

    def _cache_open_locker(function):
        def wrap(self, *args, **kwargs):
            if not hasattr(self, "contents"):
                return function(self, *args, **kwargs)
            return True
        return wrap

    @_cache_open_locker
    def open(self):
        with open(self.path, "rb") as f:
            salt = f.read(16)
            hashed_password = f.read(32)
        kdf = Scrypt(
            salt=salt,
            length=_PASSWORD_LENGTH,
            n=_PASSWORD_N,
            r=_PASSWORD_R,
            p=_PASSWORD_P,
            backend=_PASSWORD_BACKEND
        )
        try:
            kdf.verify(self.password, hashed_password)
        except InvalidKey:
            raise InvalidKey("invalid password provided")
        kdf = PBKDF2HMAC(
            algorithm=_PASSWORD_HASH,
            length=_PASSWORD_LENGTH,
            salt=salt,
            iterations=_PASSWORD_ITERATIONS,
            backend=_PASSWORD_BACKEND
        )
        key = base64.b64encode(kdf.derive(self.password))
        self._cipher = Fernet(key)
        self.contents = {}
        for name, password in self._yield_combinations():
            self.contents[name] = password
        self._trash = []

    @_requires_open_locker
    def get(self, key):
        _validate(key=key)
        if key not in self.contents:
            raise KeyError("provided key not in locker")
        return self.contents[key]

    @_requires_open_locker
    def set(self, key, value):
        _validate(key=key, value=value)
        self.contents[key] = value

    @_requires_open_locker
    def delete(self, key):
        _validate(key=key)
        if key not in self.contents:
            raise KeyError("provided key not in locker")
        self.contents.pop(key)
        self._trash.append(key)

    def close(self):
        locker = {}
        for name in self.contents:
            if name in self._trash:
                continue
            encrypted_name = self._cipher.encrypt(name)
            encrypted_password = self._cipher.encrypt(self.contents[name])
            locker[encrypted_name] = encrypted_password
        with open(self.path, "rb") as f:
            salt = f.read(16)
            hashed_password = f.read(32)
        with open(self.path, "wb") as f:
            f.write(salt)
            f.write(hashed_password)
            for name in locker:
                f.write(name)
                f.write(self.SEPARATOR)
                f.write(locker[name])
                f.write(self.NEWLINE)

        del self._cipher
        del self.contents
        del self._trash

    def __repr__(self):
        try:
            return "<Locker {}>".format(self.contents)
        except AttributeError:
            return "<Locker>"
