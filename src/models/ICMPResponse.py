import scapy.all as scapy

class ICMPResponse:
    def __init__(self):
        self.R = False
        self.DFI = None
        self.T = None
        self.TG = None
        self.CD = None

    def save_first_probe(self, response):
        if response:
            self.T = response[scapy.IP].ttl  # T: TTL value from the response
            self.CD = response[scapy.IP].id  # CD: Capture IP ID as an identifier
            self.TG = response.time  # TG: Timestamp of response
            print("First probe saved with T, TG, CD values.")

    def save_second_probe(self, response):
        if response:
            self.R = True  # R is True if both probes receive responses
            print("Second probe saved, setting R to True.")

    def __str__(self):
        return (f"IE Test Results:\n"
                f"  R: {'Y' if self.R else 'N'}\n"
                f"  DFI: {self.DFI}\n"
                f"  T: {self.T}\n"
                f"  TG: {self.TG}\n"
                f"  CD: {self.CD}\n")