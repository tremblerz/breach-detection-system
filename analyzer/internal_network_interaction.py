import multiprocessing

class InternalInteraction(multiprocessing.Process):
    """docstring for InternalInteraction"""
    def __init__(self, arg):
        super(InternalInteraction, self).__init__()
        self.arg = arg

    def run(self):
        pass
