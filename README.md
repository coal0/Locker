# Locker ![lock](https://github.com/Coal0/Locker/blob/master/assets/lock.png)
A place to keep your valuables.

---

Locker makes it easy to securely store data in a `key:value` scheme on a hard drive.<br />
Locker is presumably compatible with all versions of Python 3, including the latest 3.7 release.<br />

## Quick start
Each locker represents a storage space (file) encrypted using a separate password.
To get started, just import the `Locker` class:

```python
>>> from locker import Locker
```

Assuming you don't have a locker yet, create a new one with `Locker.create_locker`.<br />
Be sure to pass a `bytes` object as the `password` argument.

```python
>>> Locker.create_locker(
...     path="foo",
...     password=b"bar"
... )
```
###### NOTE: Creating a new vault or opening an existing one may take some time, because the password storage algorithms require lots of computational power. Please be patient.

---

Now that your locker has been created, you can load it:

```python
>>> locker = Locker(
...     path="foo",
...     password=b"bar"
... )
```

To open the locker and decrypt its contents, call `Locker.open`.<br />
To demonstrate what happens when you enter a wrong password, let's modify the `password` attribute:

```python
>>> locker.password
b'bar'
>>> locker.password = b'spam'
>>> locker.open()
Traceback (most recent call last):
...
cryptography.exceptions.InvalidKey: invalid password provided
```

As you can see, a `cryptography.exceptions.InvalidKey` exception is raised.<br />
Let's restore the original password and try opening the locker again:

```python
>>> locker.password = b'foo'
>>> locker.open()
```

The `open` call should return with no traceback.

---

With the locker being opened, let's take a look at its `contents`:

```python
>>> locker.contents
{}
```

Our locker is empty, but we can change that.<br />
You can manually add `key:value` entries to the locker, or use the convenient `get`, `set` and `delete` methods:

```python
>>> locker.set(b"foo", b"bar")
>>> locker.get(b"foo")
b'bar'
>>> locker.delete(b"foo")
>>> locker.get(b"foo")
Traceback (most recent call last):
...
KeyError: "key b'foo' not in locker"
```

Note especially how all `key:value` pairs are `bytes` objects.<br />

---

To save any changes you made, call `close`:

```python
>>> locker.close()
```

Don't forget to call this method after you're done modifying a locker, or your changes will be discarded.
