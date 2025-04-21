from scapy.all import *

def extract_n_packets(input_file, output_file, n):
	with PcapReader(input_file) as pcap_reader:
		first_n_packets = []
		for _ in range(n):
			pkt = next(pcap_reader)
			first_n_packets.append(pkt)

	if first_n_packets:
		wrpcap(output_file, first_n_packets)
		print(f"Extract successfully in {output_file}")
	else:
		print(" Failed")
if __name__ == "__main__":
	input_file = input("---INPUT FILE:")
	output_file = input("---OUTPUT FILE:")
	n = int(input("---Numbers of packet:"))
	extract_n_packets(input_file, output_file, n)

