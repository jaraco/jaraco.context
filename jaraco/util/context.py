import contextlib

@contextlib.contextmanager
def null_context():
	yield
