import contextlib


@contextlib.contextmanager
def null_context():
	yield


class ExceptionTrap(object):
	"""
	A context manager that will catch certain exceptions and provide an
	indication they occurred.

	>>> with ExceptionTrap() as trap:
	...     raise Exception()
	>>> bool(trap)
	True

	>>> with ExceptionTrap() as trap:
	...     pass
	>>> bool(trap)
	False

	>>> with ExceptionTrap(ValueError) as trap:
	...     raise ValueError("1 + 1 is not 3")
	>>> bool(trap)
	True

	>>> with ExceptionTrap(ValueError) as trap:
	...     raise Exception()
	Traceback (most recent call last):
	...
	Exception

	>>> bool(trap)
	False
	"""
	exc_info = None, None, None

	def __init__(self, exceptions=(Exception,)):
		self.exceptions = exceptions

	def __enter__(self):
		return self

	def __exit__(self, exc_type, exc_val, traceback):
		matches = exc_type and issubclass(exc_type, self.exceptions)
		if matches:
			self.exc_info = exc_type, exc_val, traceback
		return matches

	def __bool__(self):
		return bool(self.exc_info[0])
	__nonzero__ = __bool__
