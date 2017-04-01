import signal
from system_utilities import quit


def handle_ctrl_c():
    original_sigint = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, quit)
