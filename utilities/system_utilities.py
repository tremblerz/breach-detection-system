import sys

def abort(error_code = -1, error_message = None):
    """Summary
    
    Args:
        error_code (TYPE, optional): Description
        error_message (None, optional): Description
    
    Returns:
        TYPE: Description
    """
    if error_message is not None:
        print("Aborting: " + error_message)
    sys.exit(error_code)