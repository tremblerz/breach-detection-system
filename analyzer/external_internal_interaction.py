import multiprocessing


class ExternalInternalInteraction(multiprocessing.Process):
    """docstring for ExternalInternalInteraction"""

    def __init__(self, arg):
        super(ExternalInternalInteraction, self).__init__()
        self.arg = arg

    def run(self):
        pass
