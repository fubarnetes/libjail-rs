import sys

from setuptools import setup
from setuptools.command.test import test as TestCommand

try:
    from setuptools_rust import RustExtension
except ImportError:
    import subprocess
    errno = subprocess.call([sys.executable, '-m', 'pip', 'install', 'setuptools-rust'])
    if errno:
        print("Please install setuptools-rust package")
        raise SystemExit(errno)
    else:
        from setuptools_rust import RustExtension

class PyTest(TestCommand):
    user_options = []

    def run(self):
        self.run_command("test_rust")

        import subprocess
        import sys
        errno = subprocess.call(['pytest', '-v', 'tests'])
        raise SystemExit(errno)

setup_requires = ['setuptools-rust>=0.10.1']
install_requires = []
tests_require = install_requires + ['pytest', 'pytest-benchmark']

setup(
    name='jail',
    version='0.0.5',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Programming Language :: Python',
        'Programming Language :: Rust',
        'Operating System :: POSIX :: BSD :: FreeBSD',
    ],
    packages=['jail'],
    rust_extensions=[RustExtension('jail._jail', 'Cargo.toml')],
    install_requires=install_requires,
    tests_require=tests_require,
    setup_requires=setup_requires,
    include_package_data=True,
    zip_safe=False,
    cmdclass=dict(test=PyTest)
)

