# [DDC CTF 2026] Reverse Challenge 1

## THÔNG TIN BÀI CHALLENGE
- Category: Reverse Engineering
- Target File: smartgpt
- File Type: ELF 64-bit static executable, x86-64
- Difficulty:

## CÔNG CỤ SỬ DỤNG
- CLI Tools: file, strings (Sơ bộ và phân tích tĩnh)
- Python: Viết kịch bản phụ trợ để giải quyết bài toán

## QUÁ TRÌNH PHÂN TÍCH
### Bước 1: Phân tích tĩnh (Static Analysis)
Kiểm tra thông tin file bằng lệnh `file`:
```bash
$ file smartgpt
smartgpt: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=3dfe013b3027047470d1aac10a3504baf6969725, for GNU/Linux 2.6.32, stripped
```
Mặc dù kết quả trả về là một file ELF stripped (bị xóa Symbol table, gây khó khăn cho việc đọc Assembly trong IDA/Ghidra), nhưng khi sử dụng lệnh strings, phát hiện:
```bash
mpyimod01_archive
mpyimod02_importers
spyiboot01_bootstrap
ssmartgpt
blibpython3.8.so.1.0
```
Phân tích: Đây hoàn toàn không phải là một chương trình được code bằng C/C++ thuần. Các signature như mpyimod*, spyiboot* và libpython3.8.so chứng tỏ đây là một đoạn script Python đã được đóng gói (packaged) thành Standalone Executable thông qua công cụ PyInstaller.

### Bước 2: Phân tích động (dynamic Analysis)
- Khi chạy thử file, chương trình hiển thị một giao diện console có tên SmartGPT Wrapper v2.1.0. Nó cho phép người dùng nhập câu hỏi và trả về các câu trả lời tự động của AI.
- Tuy nhiên, thông qua quá trình dịch ngược, toàn bộ class SmartGPTClient và các chuỗi hội thoại thực chất chỉ là Junk code (mã rác) và các câu lệnh if/else đơn giản nhằm đánh lạc hướng (Decoy) người phân tích. Không có bất kỳ kết nối mạng thực sự nào (Offline mode).

### Bước 3: Solution
Thay vì cố gắng debug mã máy x86-64, hướng tiếp cận đúng là giải nén và decompile mã Python:

1. Sử dụng tool pyinstxtractor.py để bung nén file ELF, thu được thư mục chứa các file `.pyc` (Python Bytecode).
2. Tìm thấy file cốt lõi là `smartgpt.pyc`.
3. Sử dụng Decompiler (PyLingual/Decompyle3) để khôi phục lại Source code gốc.

Tại Source code, mục tiêu đã lộ diện rõ ràng ở phần đầu file với bình luận của tác giả: `Contains a hardcoded API key that is the flag (obfuscated).`

Tác giả đã sử dụng kỹ thuật String Obfuscation bằng cách chia nhỏ Flag ra làm 4 mảnh, mã hóa Base64 và xáo trộn vị trí của chúng:
```Python
_CRED_FRAGMENT_X = 'My05ZTNiLTU1Mw=='
_CRED_FRAGMENT_Y = 'N2QwMjI5ZTMzfQ=='
_CRED_FRAGMENT_Z = 'MjUtOTMzZi00MWM='
_CRED_FRAGMENT_W = 'ZmxhZ3szN2Y3NDI='
_CRED_REASSEMBLY_ORDER = ['W', 'Z', 'X', 'Y']
```
Hàm `_load_credentials()` làm nhiệm vụ gọi các mảnh này theo đúng trật tự W -> Z -> X -> Y và tiến hành Decode.

Lưu ý quan trọng (Pitfall): Không thể ghép nối 4 chuỗi Base64 này lại thành 1 chuỗi dài rồi mới Decode. Dấu = trong Base64 là Padding (Ký tự đệm kết thúc). Nếu để dấu = xuất hiện ở giữa chuỗi, trình giải mã sẽ báo lỗi hoặc trả về kết quả rác.

Giải pháp: Phải Decode từng mảnh một, sau đó mới nối các chuỗi rõ (Plaintext) lại với nhau.

### Bước 4: Script
Mô phỏng lại chính xác logic của tác giả để lấy cờ:
```Python
import base64

# Các mảnh mã hóa đã thu thập từ Source code
fragments = {
    'W': 'ZmxhZ3szN2Y3NDI=',
    'Z': 'MjUtOTMzZi00MWM=',
    'X': 'My05ZTNiLTU1Mw==',
    'Y': 'N2QwMjI5ZTMzfQ=='
}

# 1. Sắp xếp theo đúng thứ tự
# 2. Decode Base64 TỪNG MẢNH MỘT
# 3. Ghép chuỗi (Join)
flag = ""
for key in ['W', 'Z', 'X', 'Y']:
    flag += base64.b64decode(fragments[key]).decode('utf-8')

print("[+] Flag found:", flag)
```
## KẾT QUẢ:
Flag: flag{37f74225-933f-41c3-9e3b-5537d0229e33}

## BÀI HỌC RÚT RA
1. Đừng vội ném mọi file ELF vào IDA/Ghidra. Hãy luôn bắt đầu bằng file và strings. Nếu thấy dấu hiệu của Python/PyInstaller, quy trình RE sẽ rẽ sang một hướng hoàn toàn khác (dễ thở hơn rất nhiều).
2. Hiểu rõ về Encoding: Mã hóa Base64 có quy tắc riêng về Padding (=, ==). Việc thao tác cắt ghép chuỗi trước hay sau khi Decode sẽ dẫn đến các kết quả hoàn toàn khác nhau.
3. Mã rác (Junk code): Đôi khi 90% code của chương trình chỉ để làm cảnh. Hãy tập trung vào những metadata, hardcoded string hoặc các logic mã hóa nằm ẩn ở phần khởi tạo (Initialization).

---
Author: Dang Lam My Khanh