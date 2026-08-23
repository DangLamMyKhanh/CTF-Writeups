# [DDC CTF 2026] Reverse Challenge 2

## THÔNG TIN BÀI CHALLENGE
- Category: Reverse Engineering
- Target File: semotionnet_v2.onnx
- Concept: ONNX Protobuf parsing, IEEE-754 Float memory representation, Metadata Abuse, Repeating-Key XOR.

## CÔNG CỤ SỬ DỤNG
- Công cụ Netron: Phân tích tĩnh
- Python: Viết kịch bản phụ trợ để giải quyết bài toán

## QUÁ TRÌNH PHÂN TÍCH
### Bước 1: Phân tích tĩnh (Static Analysis)
Mục tiêu là file `emotionnet_v2.onnx`. Bằng cách phân tích tĩnh mô hình thông qua công cụ Netron (hoặc thư viện `onnx` của Python), chúng ta nhắm vào trường `metadata_props` (một Dictionary cho phép lưu trữ siêu dữ liệu tùy ý) và phát hiện 4 dấu vết cực kỳ khả nghi:
`calibration_method: weight_indexed_xor` (Thuật toán giấu tin).
`calibration_tensor: fc2.weight` (Vị trí chứa chìa khóa).
`calibration_indices: 0,3,7,11,15,19,23,27,31,35,39,43,47,51,55,59` (16 vị trí mỏ neo).
`calibration_hash: d986fbb31210b0ea217d2ff31f60fce1898eb7e05f13e2f02e7a7da6512bfbe7ddd8aab65d17e1b87633` (Chuỗi Hex dài 42 bytes, ban đầu bị nhầm là mã băm).

### Bước 2: Phân tích động (dynamic Analysis)
Quá trình phân tích động gặp phải 3 Pitfalls từ tác giả:

1. Lỗi ép kiểu toán học: Việc dùng Numpy để lấy dữ liệu rồi ép kiểu `int()` trả về kết quả sai số, do cấu trúc Mạng nơ-ron sử dụng dấu phẩy động (`Float32`). Thay vì đọc giá trị toán học, ta phải đọc dữ liệu dưới dạng bit thô bằng lệnh `.view(np.uint32)`.
2. Có giả thuyết cho rằng tác giả lén sửa các bit của tensor `fc2.weight`. Kỹ thuật so sánh (Diff) giữa `fc2.weight` và bản sao gốc `fc2.weight_t` được sử dụng nhưng không phát hiện sự sai lệch. -> Kết luận: Ma trận trọng số hoàn toàn nguyên vẹn.
3. Nhận ra chuỗi calibration_hash (dài 42 bytes) chính là Ciphertext (Bản mã) chứa lá cờ. Thuật toán `weight_indexed_xor` thực chất là dùng các byte thô của Mạng nơ-ron làm Chìa khóa để giải mã bản mã này.

### Bước 3: Solution
Kịch bản giải mã:
1. Trích xuất Ciphertext: Lấy chuỗi Hex 42 bytes từ `calibration_hash`.
2. Trích xuất Master Key: Tại tensor `fc2.weight`, lấy 8-bit cuối cùng (LSB) của các số Float nằm tại 16 vị trí `calibration_indices`. Ta thu được một Master Key dài 16 bytes.
3. Cryptography Bypass: Do độ dài Ciphertext (42 bytes) lớn hơn Master Key (16 bytes), thuật toán được sử dụng ở đây là Repeating-Key XOR. Master Key sẽ được lặp lại liên tục để XOR với toàn bộ Ciphertext cho đến khi kết thúc.

### Bước 4: Script
Mã nguồn Python khai thác tự động:
```Python
import onnx
from onnx import numpy_helper
import numpy as np

# 1. Load the target ONNX model
model = onnx.load("emotionnet_v2.onnx")

# 2. Extract Metadata properties
indices_str = next(p.value for p in model.metadata_props if p.key == "calibration_indices")
indices = [int(x) for x in indices_str.split(",")]

hex_hash = next(p.value for p in model.metadata_props if p.key == "calibration_hash")
ciphertext = bytes.fromhex(hex_hash)

# 3. Extract the Master Key from Tensor weights (Raw bytes via view)
init = next(i for i in model.graph.initializer if i.name == "fc2.weight")
W = numpy_helper.to_array(init).flatten()
raw_ints = W.view(np.uint32)

# Get 16 LSBs as the Key
master_key = [raw_ints[idx] & 0xFF for idx in indices]

# 4. Decrypt using Repeating-Key XOR
flag = ""
for i in range(len(ciphertext)):
    # Modulo operator wraps the key around
    key_byte = master_key[i % len(master_key)] 
    flag += chr(ciphertext[i] ^ key_byte)

print(f"[+] Flag found: {flag}")
```
## KẾT QUẢ:
Flag: flag{ac763fac-6e6d-46b1-9444-f1cb20b4f2ea}

## BÀI HỌC RÚT RA
1. Model Supply Chain Attack: Định dạng ONNX (Protobuf) cho phép nhúng rất nhiều metadata tùy ý. Hacker có thể lợi dụng điều này để tuồn mã độc, C&C config, hoặc đánh cắp dữ liệu mật (như bài này) mà các hệ thống Firewall/Antivirus thông thường không thể phát hiện. 
2. Repeating-Key XOR: Trong mật mã học, khi thấy dấu hiệu của dữ liệu bị lặp lại hoặc có một chuỗi dài nhưng chỉ có vài key ban đầu, hãy nghĩ ngay đến phép chia lấy dư (%) để xoay vòng chìa khóa.

---
Author: Dang Lam My Khanh