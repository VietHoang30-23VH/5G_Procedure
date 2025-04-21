import datetime
import pytz
from joblib import load
import pandas as pd


#--- Step1: Lay goi tin---->

#--- Step2: Lay 25 truong voi argus,...--->

#--- Step3: Du doan ket qua --->
# Load model
rf_model = load('my_rf_model.joblib')

# Giả sử đây là danh sách các cột theo đúng thứ tự mà model mong đợi
# Bạn cần thay thế bằng danh sách thực tế từ X_train.columns
model_columns = ['tcp', 'AckDat', 'sHops', 'Seq', 'RST', 'TcpRtt', 'REQ', 'dMeanPktSz', 
                'Offset', 'CON', 'FIN', 'sTtl', ' e        ', 'INT', 'Mean', 'Status', 
                'icmp', 'SrcTCPBase', ' e d      ', 'sMeanPktSz', 'DstLoss', 'Loss', 
                'dTtl', 'SrcBytes', 'TotBytes']

sample_dict = [
    {
        'tcp': 0, 'AckDat': 0, 'sHops': 1, 'Seq': 47138, 'RST': 0, 'TcpRtt': 0, 'REQ': 1,
        'dMeanPktSz': 0, 'Offset': 19272380, 'CON': 0, 'FIN': 0, 'sTtl': 63, ' e        ': 1,
        'INT': 0, 'Mean': 2.582307, 'Status': 1, 'icmp': 0, 'SrcTCPBase': -1, ' e d      ': 0,
        'sMeanPktSz': 42, 'DstLoss': 0, 'Loss': 0, 'dTtl': -1, 'SrcBytes': 84, 'TotBytes': 84, 
    },
    {
        'tcp': 1, 'AckDat': 0, 'sHops': 10, 'Seq': 20000, 'RST': 0, 'TcpRtt': 12, 'REQ': 0,
        'dMeanPktSz': 500, 'Offset': 10000, 'CON': 0, 'FIN': 0, 'sTtl': 64, ' e        ': 0,
        'INT': 20, 'Mean': 1.2, 'Status': 0, 'icmp': 0, 'SrcTCPBase': 0, ' e d      ': 0,
        'sMeanPktSz': 512, 'DstLoss': 0, 'Loss': 0, 'dTtl': 64, 'SrcBytes': 1024, 'TotBytes': 2048
    },
    {
        'tcp': 1, 'AckDat': 0.024088, 'sHops': 1, 'Seq': 17276, 'RST': 0, 'TcpRtt': 0.026046, 'REQ': 0,
        'dMeanPktSz': 66, 'Offset': 10098024, 'CON': 0, 'FIN': 1, 'sTtl': 63, ' e        ': 1,
        'INT': 0, 'Mean': 0, 'Status': 1, 'icmp': 0, 'SrcTCPBase': 4238886840, ' e d      ': 0,
        'sMeanPktSz': 66, 'DstLoss': 0, 'Loss': 0, 'dTtl': 59, 'SrcBytes': 66, 'TotBytes': 132
    }
]

# Tạo DataFrame và đảm bảo đúng thứ tự cột
sample_df = pd.DataFrame(sample_dict)
sample_df = sample_df[model_columns]  # Sắp xếp lại các cột theo thứ tự model mong đợi
sample_df = sample_df.fillna(0)

# Dự đoán
y_preds = rf_model.predict(sample_df)

# Hiển thị kết quả
print("\nKết quả dự đoán các mẫu:")
for idx, y_pred in enumerate(y_preds):
    try:
        label, attack_type, tool = y_pred.split('_')
    except:
        label, attack_type, tool = y_pred, 'Unknown', 'Unknown'
    current_time = datetime.datetime.now(pytz.timezone('Etc/GMT-7')).strftime("%H:%M:%S-%d/%m/%Y")
    print(f"Mẫu {idx+1} with [{current_time}]:")
    print(f"  - Label        : {label}")
    print(f"  - Attack Type  : {attack_type}")
    print(f"  - Attack Tool  : {tool}\n")