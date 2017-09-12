import os
import unittest

from context import Locker
from context import InvalidKey

FOO_NAME = "MyLocker"
FOO_PASSWORD = "MyLocker".encode()

NAME = "Secrets"
PASSWORD = "Secrets".encode()
INCORRECT_PASSWORDS = (
    "Foo".encode(),
    "Bar".encode()
)


class TestLocker(unittest.TestCase):
    def test_create_locker(self):
        Locker.create_locker(FOO_NAME, FOO_PASSWORD)
        os.remove(FOO_NAME)

    def test_meta(self):
        locker = Locker(NAME, PASSWORD)
        self.assertEqual(locker.path, os.path.abspath(NAME))
        self.assertEqual(locker.password, PASSWORD)
        with self.assertRaises(AttributeError):
            locker.contents

    def test_restrictions(self):
        locker = Locker(NAME, PASSWORD)
        with self.assertRaises(ValueError):
            locker.get("")
        with self.assertRaises(ValueError):
            locker.set("", "")
        with self.assertRaises(ValueError):
            locker.delete("")
        locker.open()
        with self.assertRaises(KeyError):
            locker.get("Foo".encode())
        locker.set("Foo".encode(), "Foo".encode())
        locker.set("Bar".encode(), "Bar".encode())
        self.assertEqual(locker.get("Foo".encode()), "Foo".encode())
        self.assertEqual(locker.get("Bar".encode()), "Bar".encode())
        locker.delete("Foo".encode())
        with self.assertRaises(KeyError):
            locker.get("Foo".encode())
        locker.delete("Bar".encode())
        locker.close()

    def test_security(self):
        for password in INCORRECT_PASSWORDS:
            locker = Locker(NAME, password)
            with self.assertRaises(InvalidKey):
                locker.open()

    def test_operations(self):
        locker = Locker(NAME, PASSWORD)
        locker.open()
        locker.set("Foo".encode(), "Foo".encode())
        locker.set("Bar".encode(), "Bar".encode())
        locker.set("Spåm".encode(), "Spåm".encode())
        locker.close()

        locker = Locker(NAME, PASSWORD)
        locker.open()
        self.assertIsInstance(locker.contents, dict)
        self.assertIn("Foo".encode(), locker.contents)
        self.assertIn("Bar".encode(), locker.contents)
        self.assertIn("Spåm".encode(), locker.contents)
        locker.delete("Foo".encode())
        locker.close()

        locker = Locker(NAME, PASSWORD)
        locker.open()
        self.assertNotIn("Foo".encode(), locker.contents)
        locker.close()

if __name__ == "__main__":
    Locker.create_locker(NAME, PASSWORD)
    unittest.main()
