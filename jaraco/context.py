import os
import argparse
import subprocess
import contextlib
import shlex
import logging
import functools
import tempfile
import shutil

try:
	import contextlib2
except Exception:
	import contextlib as contextlib2

import jaraco.apt
import yg.lockfile


def file_lines_if_exists(filename):
	"""
	Return the lines from a file as a list if the file exists, or an
	empty list otherwise.

	>>> file_lines_if_exists('/doesnotexist.txt')
	[]
	>>> file_lines_if_exists('setup.py')
	[...]
	"""
	if not os.path.isfile(filename):
		return []
	return list(open(filename))


def strip_comments(lines):
	"""
	Returns the lines from a list of a lines with comments and trailing
	whitespace removed.

	>>> strip_comments(['abc', '  ', '# def', 'egh '])
	['abc', '', '', 'egh']

	It should not remove leading whitespace
	>>> strip_comments(['  bar # baz'])
	['  bar']

	It should also strip trailing comments.
	>>> strip_comments(['abc #foo'])
	['abc']
	"""
	return [line.partition('#')[0].rstrip() for line in lines]


def data_lines_from_file(filename):
	return filter(None, strip_comments(file_lines_if_exists(filename)))


def run():
	"""
	Run a command in the context of the system dependencies.
	"""
	parser = argparse.ArgumentParser()
	parser.add_argument(
		'--deps-def',
		default=data_lines_from_file("system deps.txt")
		+ data_lines_from_file("build deps.txt"),
		help="A file specifying the dependencies (one per line)",
		type=data_lines_from_file, dest="spec_deps")
	parser.add_argument(
		'--dep', action="append", default=[],
		help="A specific dependency (multiple allowed)", dest="deps")
	parser.add_argument(
		'command', type=shlex.split,
		default=shlex.split("python2.7 setup.py test"),
		help="Command to invoke in the context of the dependencies")
	parser.add_argument(
		'--do-not-remove', default=False, action="store_true",
		help="Keep any installed packages")
	parser.add_argument(
		'--aggressively-remove', default=False,
		action="store_true",
		help="When removing packages, also remove those automatically installed"
		" as dependencies")
	parser.add_argument(
		'-l', '--log-level', default=logging.INFO,
		type=log_level, help="Set log level (DEBUG, INFO, WARNING, ERROR)")
	args = parser.parse_args()
	logging.basicConfig(level=args.log_level)
	context = dependency_context(
		args.spec_deps + args.deps,
		aggressively_remove=args.aggressively_remove)
	with context as to_remove:
		if args.do_not_remove:
			del to_remove[:]
		raise SystemExit(subprocess.Popen(args.command).wait())


def log_level(level_string):
	"""
	Return a log level for a string
	"""
	return getattr(logging, level_string.upper())


@contextlib.contextmanager
def dependency_context(package_names, aggressively_remove=False):
	"""
	Install the supplied packages and yield. Finally, remove all packages
	that were installed.
	Currently assumes 'aptitude' is available.
	"""
	installed_packages = []
	log = logging.getLogger(__name__)
	try:
		if not package_names:
			logging.debug('No packages requested')
		if package_names:
			lock = yg.lockfile.FileLock(
				'/tmp/.pkg-context-lock',
				timeout=30 * 60)
			log.info('Acquiring lock to perform install')
			lock.acquire()
			log.info('Installing ' + ', '.join(package_names))
			output = subprocess.check_output(
				['sudo', 'aptitude', 'install', '-y'] + package_names,
				stderr=subprocess.STDOUT,
			)
			log.debug('Aptitude output:\n%s', output)
			installed_packages = jaraco.apt.parse_new_packages(
				output,
				include_automatic=aggressively_remove)
			if not installed_packages:
				lock.release()
			log.info('Installed ' + ', '.join(installed_packages))
		yield installed_packages
	except subprocess.CalledProcessError:
		log.error("Error occurred installing packages")
		raise
	finally:
		if installed_packages:
			log.info('Removing ' + ','.join(installed_packages))
			subprocess.check_call(
				['sudo', 'aptitude', 'remove', '-y'] + installed_packages,
				stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
			)
			lock.release()


@contextlib.contextmanager
def pushd(dir):
	orig = os.getcwd()
	os.chdir(dir)
	try:
		yield dir
	finally:
		os.chdir(orig)


@contextlib.contextmanager
def tarball_context(url, target_dir=None, runner=None, pushd=pushd):
	"""
	Get a tarball, extract it, change to that directory, yield, then
	clean up.
	`runner` is the function to invoke commands.
	`pushd` is a context manager for changing the directory.
	"""
	if target_dir is None:
		target_dir = os.path.basename(url).replace('.tar.gz', '').replace(
			'.tgz', '')
	if runner is None:
		runner = functools.partial(subprocess.check_call, shell=True)
	# In the tar command, use --strip-components=1 to strip the first path and
	#  then
	#  use -C to cause the files to be extracted to {target_dir}. This ensures
	#  that we always know where the files were extracted.
	runner('mkdir {target_dir}'.format(**vars()))
	try:
		getter = 'wget {url} -O -'
		extract = 'tar x{compression} --strip-components=1 -C {target_dir}'
		cmd = ' | '.join((getter, extract))
		runner(cmd.format(compression=infer_compression(url), **vars()))
		with pushd(target_dir):
			yield target_dir
	finally:
		runner('rm -Rf {target_dir}'.format(**vars()))


def infer_compression(url):
	"""
	Given a URL or filename, infer the compression code for tar.
	"""
	# cheat and just assume it's the last two characters
	compression_indicator = url[-2:]
	mapping = dict(
		gz='z',
		bz='j',
		xz='J',
	)
	# Assume 'z' (gzip) if no match
	return mapping.get(compression_indicator, 'z')


@contextlib.contextmanager
def temp_dir(remover=shutil.rmtree):
	"""
	Create a temporary directory context. Pass a custom remover
	to override the removal behavior.
	"""
	temp_dir = tempfile.mkdtemp()
	try:
		yield temp_dir
	finally:
		remover(temp_dir)


@contextlib.contextmanager
def repo_context(url, branch=None, quiet=True, dest_ctx=temp_dir):
	"""
	Check out the repo indicated by url.

	If dest_ctx is supplied, it should be a context manager
	to yield the target directory for the check out.
	"""
	exe = 'git' if 'git' in url else 'hg'
	with dest_ctx() as repo_dir:
		cmd = [exe, 'clone', url, repo_dir]
		if branch:
			cmd.extend(['--branch', branch])
		devnull = open(os.path.devnull, 'w')
		stdout = devnull if quiet else None
		subprocess.check_call(cmd, stdout=stdout)
		yield repo_dir


@contextlib.contextmanager
def null():
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


class suppress(contextlib2.suppress, contextlib2.ContextDecorator):
	"""
	A version of contextlib.suppress with decorator support.

	>>> @suppress(KeyError)
	... def key_error():
	...     {}['']
	>>> key_error()
	"""
