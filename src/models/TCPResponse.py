import scapy.all as scapy

class TCPResponse:
    def __init__(self):
        self.SEQ = {}
        self.OPS = []
        self.WIN = []
        self.T1 = {}
        self.seq_numbers = []
        self.timestamps = []
        self.ip_ids = []

    def save_response(self, response, probe_number):
        if response and scapy.TCP in response:
            tcp_layer = response[scapy.TCP]
            ip_layer = response[scapy.IP]
            
            # Save TCP options, window size, sequence number, timestamp, and IP ID for each probe
            self.OPS.append(tcp_layer.options)
            self.WIN.append(tcp_layer.window)
            self.seq_numbers.append(tcp_layer.seq)
            self.timestamps.append(tcp_layer.options[3][1][0] if "Timestamp" in dict(tcp_layer.options) else None)
            self.ip_ids.append(ip_layer.id)

            if probe_number == 1:
                # T1 tests: For probe #1 only
                self.T1['R'] = "Y" if response else "N"
                self.T1['DF'] = "Y" if ip_layer.flags.DF else "N"
                self.T1['T'] = ip_layer.ttl
                self.T1['TG'] = response.time
                self.T1['W'] = tcp_layer.window
                self.T1['S'] = ip_layer.src
                self.T1['A'] = ip_layer.id

    def calculate_seq_results(self):
        # Calculate GCD for sequence number differences
        if len(self.seq_numbers) > 1:
            seq_diffs = np.diff(self.seq_numbers)
            self.SEQ['GCD'] = int(np.gcd.reduce(seq_diffs)) if np.gcd.reduce(seq_diffs) > 0 else "Undefined"

        # Calculate ISR (Initial Sequence Rate)
        if len(self.timestamps) > 1:
            time_diffs = np.diff(self.timestamps)
            if all(time_diffs):
                self.SEQ['ISR'] = int(np.mean(seq_diffs / time_diffs))

        # Calculate TI (Time Interval between packets)
        self.SEQ['TI'] = [round(time_diffs[i] * 1000, 2) for i in range(len(time_diffs))]

        # Calculate II (IP ID Increment between packets)
        if len(self.ip_ids) > 1:
            self.SEQ['II'] = [self.ip_ids[i + 1] - self.ip_ids[i] for i in range(len(self.ip_ids) - 1)]

        # Sequence Stepping (SS): Difference between sequence numbers
        self.SEQ['SS'] = seq_diffs.tolist() if seq_diffs.size > 0 else "Not enough data"

        # Placeholder for SP and TS, which are more complex
        self.SEQ['SP'] = "Placeholder for Sequence Periodicity"
        self.SEQ['TS'] = "Placeholder for Timestamp Sequence"

    def __str__(self):
        return (f"SEQ Results: {self.SEQ}\n"
                f"OPS Results: {self.OPS}\n"
                f"WIN Results: {self.WIN}\n"
                f"T1 Test Results: {self.T1}\n")