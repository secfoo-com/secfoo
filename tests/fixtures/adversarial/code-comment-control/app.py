import subprocess

def inspect_host(host):
    return subprocess.check_output("ping -c 1 " + host, shell=True)
