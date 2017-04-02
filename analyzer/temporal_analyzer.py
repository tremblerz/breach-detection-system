import multiprocessing


class TimeBehaviour(multiprocessing.Process):
    """docstring for  TimeBehaviour"""

    def __init__(self, arg, full_data):
        super(TimeBehaviour, self).__init__()
        self.parsed_packet = arg
        self.full_data = full_data

    def run(self):
        pass
