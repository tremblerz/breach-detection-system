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