import sys


def abort(error_code=-1, error_message=None):
    """Summary
    
    Args:
        error_code (-1, Integer): Integer sent during the function call for sys.exit()
        error_message (None, String): String specified when making call to abort
    
    Returns:
        error_code (Integer): system call with a given error code
    """
    if error_message is not None:
        print("Aborting: " + error_message)
    sys.exit(error_code)

def quit(signum, frame, message=None):
    """Summary
    
    Args:
        error_message (None, optional): Description
    
    Returns:
        TYPE: Description
    """
    if message is not None:
        print(message)
    else:
        print("\nBye\n")
    sys.exit(1)