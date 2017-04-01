import multiprocessing
from internal_network_interaction import InternalInteraction
from external_internal_interaction import ExternalInternalInteraction
from system_behaviour import SystemBehaviour

class analyzerSchedular(multiprocessing.Process):
    """Summary
    """
    def __init__(self, arg):
        super(Sniffer, self).__init__()
        self.parsed_packet = arg['parsed_packet']
        self.analysis = []

    def run(self):
        internal_analyzer = InternalInteraction(self.parsed_packet)
        external_analyzer = ExternalInternalInteraction(self.parsed_packet)
        system_analyzer = SystemBehaviour(self.parsed_packet)

        analysis['internal'] = internal_analyzer.start()
        analysis['external'] = external_analyzer.start()
        analysis['system'] = system_analyzer.start()

        print(analysis)