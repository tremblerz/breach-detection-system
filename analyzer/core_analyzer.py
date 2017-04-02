import multiprocessing
from internal_network_interaction import InternalInteraction
from external_internal_interaction import ExternalInternalInteraction
from behaviour import SystemBehaviour
from temporal_analyzer import TimeBehaviour


class analyzerSchedular(multiprocessing.Process):
    """Summary
    """

    def __init__(self, arg, full_data):
        super(analyzerSchedular, self).__init__()
        self.parsed_packet = arg
        self.analysis = {}
        self.full_data = full_data
        print(self.full_data)

    def run(self):
        #print(self.parsed_packet)
        internal_analyzer = InternalInteraction(self.parsed_packet)
        external_analyzer = ExternalInternalInteraction(self.parsed_packet)
        system_analyzer = SystemBehaviour(self.parsed_packet)
        temporal_analyzer = TimeBehaviour(self.parsed_packet, self.full_data)

        internal_analyzer.start()
        external_analyzer.start()
        system_analyzer.start()

        #print(self.analysis)
