import multiprocessing

class  SystemBehaviour(multiprocessing.Process):
    """docstring for  SystemBehaviour"""
    def __init__(self, arg):
        super( SystemBehaviour, self).__init__()
        self.arg = arg

    def run(self):
        pass