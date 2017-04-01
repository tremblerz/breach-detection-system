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
    file_data = pickle.load(filename)
    return file_data