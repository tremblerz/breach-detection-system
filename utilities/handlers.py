import signal
from system_utilities import quit
import pickle



def handle_ctrl_c():
    original_sigint = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, quit)

def file_load(filename):
    """Summary
    
    Args:
        filename (TYPE): Description
    
    Returns:
        TYPE: Description
    """
    with open(filename) as f:
        content = f.readlines()
    content = [x.strip() for x in content]
    content = filter(None, content)
    return content
