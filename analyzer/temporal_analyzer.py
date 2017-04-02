import multiprocessing


class TimeBehaviour(multiprocessing.Process):
    """docstring for  TimeBehaviour"""

    def __init__(self, arg, full_data):
        super(TimeBehaviour, self).__init__()
        self.parsed_packet = arg
        self.full_data = full_data

    def validate(self, ip1, ip2):
        if ip1 == ip2:
            return None
        interaction_time = []
        for data in self.full_data:
            if ip1 == data['source'] and ip2 == data['destination']:
                interaction_time.append(data['timestamp'])
            elif ip1 == data['destination'] and ip2 == data['source']:
                interaction_time.append(data['timestamp'])
            else:
                continue
        print(ip1)
        print(ip2)
        print(interaction_time)
        return len(interaction_time) > 10

    def find_by_src(self):
        suspicion = 0
        for packet in self.full_data:
            if self.parsed_packet['IP']['SRC_addr'] == packet['source']:
                if self.validate(self.parsed_packet['IP']['SRC_addr'], packet['source']):
                    suspicion += 1
            elif self.parsed_packet['IP']['SRC_addr'] == packet['destination']:
                if self.validate(self.parsed_packet['IP']['SRC_addr'], packet['destination']):
                    suspicion += 1
            else:
                continue

        return suspicion

    def run(self):
        suspicion = self.find_by_src()