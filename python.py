import datetime
import pytz
import numpy as np
import random
from joblib import load
import pandas as pd
from scapy.all import rdpcap, IP, TCP

# Load model
rf_model = load('my_rf_model.joblib')
model_columns = ['tcp', 'AckDat', 'sHops', 'Seq', 'RST', 'TcpRtt', 'REQ', 'dMeanPktSz',
                'Offset', 'CON', 'FIN', 'sTtl', ' e        ', 'INT', 'Mean', 'Status',
                'icmp', 'SrcTCPBase', ' e d      ', 'sMeanPktSz', 'DstLoss', 'Loss',
                'dTtl', 'SrcBytes', 'TotBytes']
# done
def detect_tcp_packet(packet):
    """Detect if a packet is TCP."""
    if packet.haslayer("IP"):
        if packet["IP"].proto == 6:
            return 1
    if packet.haslayer("TCP"):
        return 1
    return 0
# done
def detect_icmp_packet(packet):
    """Detect if a packet is ICMP."""
    if packet.haslayer("IP"):
        if packet["IP"].proto == 1:
            return 1
    if packet.haslayer("ICMP"):
        return 1
    return 0
# done
def calculate_total_bytes(packet):
    """Calculate the total bytes of a packet."""
    return len(packet)
# done
def calculate_mean(packet_list):
    """Calculate the mean packet size."""
    if not packet_list:
        return 0
    packet_sizes = [len(pkt) for pkt in packet_list]
    return sum(packet_sizes) / len(packet_sizes)

def get_status(packet):
    """Determine packet status (request/response)."""
    if packet.haslayer(TCP):
        if packet[TCP].sport > 1024 and packet[TCP].dport < 1024:
            return 0  # Request
        else:
            return 1  # Response
    return 0

def get_shops(packet):
    """Calculate source hops based on IP TTL."""
    if packet.haslayer(IP):
        ttl = packet[IP].ttl
        if ttl <= 64:
            initial_ttl = 64
        elif ttl <= 128:
            initial_ttl = 128
        else:
            initial_ttl = 255
        return initial_ttl - ttl
    return 0

def get_seq(packet):
    """Extract TCP sequence number."""
    if packet.haslayer(TCP):
        return packet[TCP].seq
    return 0

def calculate_loss(packet_list, direction='dst'):
    """Calculate packet loss ratio."""
    if not packet_list:
        return 0
    return np.random.uniform(0, 0.1)

def get_ttl(packet, direction='dst'):
    """Get TTL value."""
    if packet.haslayer(IP):
        return packet[IP].ttl
    return 0

def get_ackdat(packet):
    """
    Extract TCP acknowledgment data.
    Returns 1 if ACK flag is set, 0 otherwise.
    """
    if packet.haslayer(TCP):
        if packet[TCP].flags & 0x10:  # Check if ACK flag is set
            return 1
    return 0

def get_rst(packet):
    """
    Extract TCP RST flag.
    Returns 1 if RST flag is set, 0 otherwise.
    """
    if packet.haslayer(TCP):
        if packet[TCP].flags & 0x04:  # Check if RST flag is set
            return 1
    return 0

def calculate_tcp_rtt(packet_list):
    """
    Estimate TCP Round Trip Time.
    In a real implementation, this would measure time between SYN and SYN-ACK
    or between data packets and their ACKs.
    """
    # Simplified version for demo
    return random.uniform(0.001, 0.1)  # Return a value between 1-100ms

def get_req(packet):
    """
    Identify if packet is a request.
    Returns 1 if it's a request packet, 0 otherwise.
    """
    if packet.haslayer(TCP):
        # Simplified heuristic: if destination port is well-known, it's likely a request
        if packet[TCP].dport < 1024:
            return 1
    return 0

def calculate_mean_pkt_sz(packet_list, direction='dst'):
    """
    Calculate mean packet size for specific direction.
    direction can be 'dst' or 'src'.
    """
    if not packet_list:
        return 0
    
    # In a real implementation, you would filter packets by direction
    # Here we're just returning a slightly modified mean for demonstration
    mean_size = calculate_mean(packet_list)
    if direction == 'dst':
        return mean_size * random.uniform(0.9, 1.1)
    else:  # src
        return mean_size * random.uniform(0.8, 1.2)

def get_offset(packet):
    """
    Extract TCP header offset/data offset.
    """
    if packet.haslayer(TCP):
        return packet[TCP].dataofs
    return 0

connections = {}

def get_con(packet):
    """
    Track TCP connection state and determine if a packet belongs to an established connection.
    Returns 1 if the connection is established, 0 otherwise.
    """
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src = packet[IP].src
        dst = packet[IP].dst
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        flags = packet[TCP].flags
        
        key = (src, sport, dst, dport)
        rev_key = (dst, dport, src, sport)
        
        # Track connection state
        if (flags & 0x02) and not (flags & 0x10):  # SYN
            connections[key] = 'SYN'
            return 0  # Not established yet
        elif (flags & 0x12) == 0x12:  # SYN-ACK (both SYN and ACK flags)
            if rev_key in connections and connections[rev_key] == 'SYN':
                connections[rev_key] = 'SYN-ACK'
            return 0  # Not established yet
        elif (flags & 0x10) == 0x10:  # ACK
            if rev_key in connections and connections[rev_key] == 'SYN-ACK':
                connections[rev_key] = 'CON'
                connections[key] = 'CON'  # Mark both directions as established
        
        # Check if this connection is established
        if key in connections and connections[key] == 'CON':
            return 1
        if rev_key in connections and connections[rev_key] == 'CON':
            return 1
            
    return 0

def get_fin(packet):
    """
    Check if packet is a connection termination packet.
    Returns 1 if FIN flag is set, 0 otherwise.
    """
    if packet.haslayer(TCP):
        if packet[TCP].flags & 0x01:
            return 1
    return 0

def get_e(packet):
    """
    Calculate 'e' value (appears to be some feature with spaces in name).
    For demo purposes, return a random value.
    """
    return random.uniform(0, 1)

def get_int(packet):
    """
    Calculate 'INT' value (could be related to interval).
    For demo purposes, return a random value.
    """
    return random.uniform(0, 10)

def get_src_tcp_base(packet):
    """
    Extract source TCP base sequence number.
    """
    if packet.haslayer(TCP):
        return packet[TCP].seq
    return 0

def get_src_bytes(packet):
    """
    Calculate bytes from source to destination.
    """
    if packet.haslayer(IP):
        return packet[IP].len - 20  # IP header size
    return 0

def analyze_pcap(pcap_file):
    """
    Analyze a pcap file and create a list of dictionaries with all required fields.
    """
    try:
        # Read the pcap file
        packets = rdpcap(pcap_file)
        print(f"Successfully read {len(packets)} packets from {pcap_file}")
        
        # Calculate global metrics
        mean_size = calculate_mean(packets)
        dst_loss = calculate_loss(packets, 'dst')
        src_loss = calculate_loss(packets, 'src')
        tcp_rtt = calculate_tcp_rtt(packets)
        d_mean_pkt_sz = calculate_mean_pkt_sz(packets, 'dst')
        s_mean_pkt_sz = calculate_mean_pkt_sz(packets, 'src')
        
        # Create a list to store dictionaries for each packet
        packet_list = []
        
        # Process each packet
        for i, packet in enumerate(packets):
            is_tcp = detect_tcp_packet(packet)
            is_icmp = detect_icmp_packet(packet)
            tot_bytes = calculate_total_bytes(packet)
            status = get_status(packet)
            shops = get_shops(packet)
            seq = get_seq(packet)
            dttl = get_ttl(packet, 'dst')
            sttl = get_ttl(packet, 'src')
            ackdat = get_ackdat(packet)
            rst = get_rst(packet)
            req = get_req(packet)
            offset = get_offset(packet)
            con = get_con(packet)
            fin = get_fin(packet)
            e_value = get_e(packet)
            int_value = get_int(packet)
            src_tcp_base = get_src_tcp_base(packet)
            src_bytes = get_src_bytes(packet)
            
            # Create dictionary with all required columns
            packet_dict = {
                'tcp': is_tcp,
                'icmp': is_icmp,
                'TotBytes': tot_bytes,
                'Mean': mean_size,
                'Status': status, 
                'sHops': shops,
                'Seq': seq,
                'DstLoss': dst_loss,
                'Loss': src_loss,
                'dTtl': dttl,
                'sTtl': sttl,
                'AckDat': ackdat,
                'RST': rst,
                'TcpRtt': tcp_rtt,
                'REQ': req,
                'dMeanPktSz': d_mean_pkt_sz,
                'Offset': offset,
                'CON': con,
                'FIN': fin,
                ' e        ': e_value,
                'INT': int_value,
                'SrcTCPBase': src_tcp_base,
                ' e d      ': e_value * 2,  # Another e-related field with a different value
                'sMeanPktSz': s_mean_pkt_sz,
                'SrcBytes': src_bytes
            }
            
            # Add to the list
            packet_list.append(packet_dict)
            
        # Summary
        tcp_count = sum(pkt['tcp'] for pkt in packet_list)
        icmp_count = sum(pkt['icmp'] for pkt in packet_list)
        total_bytes = sum(pkt['TotBytes'] for pkt in packet_list)
        print(f"\nSummary: {tcp_count} TCP packets and {icmp_count} ICMP packets out of {len(packets)} total packets")
        
        return packet_list
    
    except Exception as e:
        print(f"Error processing the pcap file: {str(e)}")
        return []

# Execute with the specified file
if __name__ == "__main__":
    pcap_file = "30packet.pcapng"
    results = analyze_pcap(pcap_file)
    print(f'{results}')
    # Create DataFrame with all required columns
    sample_df = pd.DataFrame(results)
    
    # Ensure all model columns are present
    for col in model_columns:
        if col not in sample_df.columns:
            sample_df[col] = 0
    
    # Reorder columns to match model expectations
    sample_df = sample_df[model_columns]
    
    # Predict
    y_preds = rf_model.predict(sample_df)
    
    # Display results
    print("\nKết quả dự đoán các mẫu:")
    for idx, y_pred in enumerate(y_preds):
        try:
            label, attack_type, tool = y_pred.split('_')
        except:
            label, attack_type, tool = y_pred, 'Unknown', 'Unknown'
        
        current_time = datetime.datetime.now(pytz.timezone('Etc/GMT-7')).strftime("%H:%M:%S-%d/%m/%Y")
        print(f"Sample {idx+1} with [{current_time}]:")
        print(f"  - Label        : {label}")
        print(f"  - Attack Type  : {attack_type}")
        print(f"  - Attack Tool  : {tool}\n")