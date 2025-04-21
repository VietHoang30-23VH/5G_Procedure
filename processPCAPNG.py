import subprocess
import pandas as pd
import os

def pcapng_to_features(input_pcapng, output_csv='final_features.csv'):
    """
    Chuyển đổi file PCAPNG sang các features cần thiết cho model
    
    Args:
        input_pcapng: Đường dẫn đến file input.pcapng
        output_csv: Đường dẫn đầu ra cho file CSV chứa features
    """
    
    # 1. Chuyển đổi PCAPNG sang Argus format
    argus_file = 'TestTCP.argus'
    print(f"Converting {input_pcapng} to Argus format...")
    subprocess.run(['argus', '-r', input_pcapng, '-w', argus_file], check=True)
    
    # 2. Trích xuất các trường cơ bản từ Argus
    csv_file = 'temp_flow_data.csv'
    print("Extracting basic flow features...")
    subprocess.run([
        'ra', '-r', argus_file, 
        '-s', 'proto', 'ackdat', 'shops', 'seq', 'state', 'tcprtt', 
        'offset', 'sttl', 'sdsb', 'ddsb', 'mean', 'cause', 'stcpb', 
        'dloss', 'loss', 'dttl', 'sbytes', 'bytes', 'dpkts', 'spkts'
        #'-c', ','
    ], stdout=open(csv_file, 'w'), check=True)
    
    # 3. Xử lý dữ liệu và tính toán các features cần thiết
    print("Processing and calculating derived features...")
    df = pd.read_csv(csv_file)
    
    # Xử lý các trường protocol
    df['tcp'] = df['proto'].apply(lambda x: 1 if str(x).lower() == 'tcp' else 0)
    df['icmp'] = df['proto'].apply(lambda x: 1 if str(x).lower() == 'icmp' else 0)
    
    # Xử lý các trường state flags
    df['state'] = df['state'].astype(str)
    df['RST'] = df['state'].apply(lambda x: 1 if 'RST' in x else 0)
    df['REQ'] = df['state'].apply(lambda x: 1 if 'REQ' in x else 0)
    df['CON'] = df['state'].apply(lambda x: 1 if 'CON' in x else 0)
    df['FIN'] = df['state'].apply(lambda x: 1 if 'FIN' in x else 0)
    df['INT'] = df['state'].apply(lambda x: 1 if 'INT' in x else 0)
    
    # Xử lý các trường đặc biệt
    df[' e        '] = df['sdsb']
    df[' e d      '] = df['ddsb']
    df['Status'] = df['cause']
    
    # Tính toán các trường mean packet size
    df['dMeanPktSz'] = df['bytes'] / df['dpkts'].replace(0, 1)  # Tránh chia cho 0
    df['sMeanPktSz'] = df['sbytes'] / df['spkts'].replace(0, 1)  # Tránh chia cho 0
    
    # Chuẩn bị DataFrame cuối cùng
    final_df = df.rename(columns={
        'ackdat': 'AckDat',
        'shops': 'sHops',
        'seq': 'Seq',
        'tcprtt': 'TcpRtt',
        'offset': 'Offset',
        'sttl': 'sTtl',
        'mean': 'Mean',
        'stcpb': 'SrcTCPBase',
        'dloss': 'DstLoss',
        'loss': 'Loss',
        'dttl': 'dTtl',
        'sbytes': 'SrcBytes',
        'bytes': 'TotBytes'
    })
    
    # Chọn các cột theo thứ tự yêu cầu
    final_columns = [
        'tcp', 'AckDat', 'sHops', 'Seq', 'RST', 'TcpRtt', 'REQ', 
        'dMeanPktSz', 'Offset', 'CON', 'FIN', 'sTtl', ' e        ', 
        'INT', 'Mean', 'Status', 'icmp', 'SrcTCPBase', ' e d      ', 
        'sMeanPktSz', 'DstLoss', 'Loss', 'dTtl', 'SrcBytes', 'TotBytes'
    ]
    
    final_df = final_df[final_columns]
    
    # Lưu kết quả
    final_df.to_csv(output_csv, index=False)
    print(f"Features extracted successfully to {output_csv}")
    
    # Dọn dẹp file tạm
    os.remove(argus_file)
    os.remove(csv_file)
    
    return final_df

# Sử dụng hàm
if __name__ == "__main__":
    input_pcap=input("- Input file:")
    features_df = pcapng_to_features(input_pcap)
    print(features_df.head())