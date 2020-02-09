from subprocess import PIPE, run


def command_seq(sequence, password=''):
    s = run(sequence, shell=True, stdout=PIPE, stderr=PIPE, input=bytes(password + '\n', 'utf-8'))
    res = [s.stdout.decode('utf-8'), s.stderr.decode('utf-8')]
    return res

