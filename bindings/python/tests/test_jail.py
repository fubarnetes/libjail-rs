import pytest

from jail import StoppedJail, RunningJail, Jls


def start_stop(s):
    j = s.start()
    j.stop()

def test_start_stop_jail(benchmark):
    s = StoppedJail('/rescue')

    benchmark(start_stop, s)


def get_hostname(j):
    return j.parameters['host.hostname']

def test_get_parameter(benchmark):
    s = StoppedJail('/rescue', parameters={'host.hostname': 'test'})
    j = s.start()
    hostname = benchmark(get_hostname, j)
    assert hostname == 'test'
    j.stop()


def spawn_hello_world(j):
    child = j.spawn(['/echo', 'hello world'])
    child.wait()

def test_spawn(benchmark):
    s = StoppedJail('/rescue')
    j = s.start()
    benchmark(spawn_hello_world, j)
    j.stop()


import subprocess
def popen_hello_world(j):
    child = subprocess.Popen(['/echo', 'hello world'], preexec_fn=lambda: j.attach())
    child.wait()

def test_popen(benchmark):
    s = StoppedJail('/rescue')
    j = s.start()
    benchmark(popen_hello_world, j)
    j.stop()

def jls_jids():
    return set(j.jid for j in Jls())

def test_jls(benchmark):
    # start 100 jails
    s = StoppedJail('/rescue')
    started = [s.start() for _ in range(100)]
    started_jids = set(j.jid for j in started)

    jids = benchmark(jls_jids)

    for r in started:
        r.stop();

    assert started_jids <= jids


def get_jail_by_name(name):
    r = RunningJail(name)
    hostname = r.parameters['host.hostname']
    del r
    return hostname

def test_get_jail_by_name(benchmark):
    s = StoppedJail('/rescue', name="foobar", parameters={"host.hostname": "foobar"})
    r = s.start()

    hostname = benchmark(get_jail_by_name, "foobar")

    r.stop()

    assert hostname == "foobar"

def test_stdio() :
    s = StoppedJail('/rescue')
    r = s.start()

    c = r.spawn(["cat"], env={"PATH": "/"})
    c.write_stdin(bytearray(b'hello world\n'))
    assert c.read_stdout(100) == bytearray(b'hello world\n')
    assert c.wait().code == 0

    r.stop()
