import multiprocessing
from internal_network_interaction import InternalInteraction
from external_internal_interaction import ExternalInternalInteraction
from system_behaviour import SystemBehaviour


class analyzerSchedular(multiprocessing.Process):
    """Summary
    """

    def __init__(self, arg):
        super(analyzerSchedular, self).__init__()
        self.parsed_packet = arg
        self.analysis = {}

    def run(self):
        #print(self.parsed_packet)
        internal_analyzer = InternalInteraction(self.parsed_packet)
        external_analyzer = ExternalInternalInteraction(self.parsed_packet)
        system_analyzer = SystemBehaviour(self.parsed_packet)

        self.analysis['internal'] = internal_analyzer.start()
        self.analysis['external'] = external_analyzer.start()
        self.analysis['system'] = system_analyzer.start()

        print(self.analysis)
