import subprocess
import base64
import os


ADDR = "unix:path=/dev/shm/system_bus_socket"


def wait_for_dbus_daemon() -> str:
    p = subprocess.Popen(
        [
            "/usr/bin/dbus-daemon",
            "--system",
            "--nofork",
            "--nosyslog",
            "--print-address",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )

    for line in iter(p.stdout.readline, b""):
        decoded_line = line.decode("utf-8").strip()
        if decoded_line.startswith("unix:"):
            return decoded_line
    # something wrong happens...
    print("dbus-daemon does not start properly", p.stderr.read())
    exit(1)


def start_flagserver() -> None:
    p = subprocess.Popen(
        ["/usr/bin/flagserver"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env={"DBUS_SYSTEM_BUS_ADDRESS": ADDR},
    )

    for line in iter(p.stdout.readline, b""):
        decoded_line = line.decode("utf-8").strip()
        if decoded_line.startswith("Name acquired"):
            return
    raise RuntimeError("flagserver does not start properly")


if __name__ == "__main__":
    binary = input("Base64 of binary: ")
    with open("/dev/shm/executable", "wb") as f:
        f.write(base64.b64decode(binary))
    os.chmod("/dev/shm/executable", 0o555)
    assert wait_for_dbus_daemon()
    start_flagserver()
    output = subprocess.run(
        [
            "/dev/shm/executable",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        user="nobody",
        group="nogroup",
        env={"DBUS_SYSTEM_BUS_ADDRESS": ADDR},
    )
    stdout = output.stdout[:8192].decode()
    stderr = output.stderr[:8192].decode()
    print("Return code:", output.returncode)
    print("stdout (标准输出，前 8192 个字节):")
    print(stdout)
    print("stderr (标准错误，前 8192 个字节):")
    print(stderr)
