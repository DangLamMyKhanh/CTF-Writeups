import struct

# 1. Đọc tệp tini_rev
try:
    with open("tini_rev", "rb") as f:
        file_data = f.read()
except FileNotFoundError:
    print("Không tìm thấy file tini_rev trong thư mục hiện tại!")
    exit()

# 2. Trích xuất dữ liệu tĩnh (ImageBase = 0x400000)
# 0x4001b8 -> offset 0x1b8. Đọc 227 words (454 bytes)
words_data = file_data[0x1b8 : 0x1b8 + 454]
encrypted_words = list(struct.unpack(f"<{len(words_data)//2}H", words_data))

# 0x40037e -> offset 0x37e. Đọc 10 bytes cho số lượng run của 10 dòng
meta_array = list(file_data[0x37e : 0x37e + 10])

print("Đang tiến hành quét toán học tìm KEY giải mã chuẩn...")
correct_key = None

# Quét tất cả các khóa KEY khả thi (EBP thường nằm trong khoảng 400 đến 800)
for key in range(1, 5000):
    decrypted = [(w - key) & 0xFFFF for w in encrypted_words]
    idx = 3  # Bỏ qua 3 word đầu tiên (tương ứng lệnh ADD R15, 6 ở đầu hàm)
    valid = True
    
    for row in range(10):
        num_runs = meta_array[row]
        
        # Tiêu thụ đúng 2 words (như chỉ thị ADD R15, 2 trước và sau khi đọc)
        if idx + 2 >= len(decrypted):
            valid = False
            break
        idx += 2
        
        row_sum = 0
        for r in range(num_runs - 1):
            if idx >= len(decrypted):
                valid = False
                break
            run_len = decrypted[idx]
            idx += 1
            row_sum += run_len
            
        # Tổng độ rộng một dòng không được vượt quá 140 kí tự
        if row_sum > 140:
            valid = False
            break
            
    if valid and idx <= len(decrypted):
        correct_key = key
        print(f"    [+] Tìm thấy KEY chuẩn xác: {key} (Tổng mã ASCII của Flag)!")
        break

if correct_key is None:
    print("Không tìm thấy khóa hợp lệ. Vui lòng kiểm tra lại cấu trúc file.")
    exit()

# 3. Tiến hành giải nén ảnh RLE chứa Flag bằng khóa đúng tìm được
decrypted = [(w - correct_key) & 0xFFFF for w in encrypted_words]
idx = 3
ascii_art = []

for row in range(10):
    num_runs = meta_array[row]
    start_word = decrypted[idx + 1]
    idx += 2
    
    char_flag = (start_word & 1)
    current_char = chr(0x30 + char_flag) # '0' hoặc '1'
    
    row_str = ""
    remaining_width = 140
    
    for r in range(num_runs - 1):
        run_len = decrypted[idx]
        idx += 1
        actual_len = min(run_len, remaining_width)
        row_str += current_char * actual_len
        remaining_width -= actual_len
        current_char = '1' if current_char == '0' else '0'
        
    if remaining_width > 0:
        row_str += current_char * remaining_width
        
    ascii_art.append(row_str)

# XUẤT RA FILE TXT ĐỂ ĐỌC DỄ DÀNG HƠN
output_art_file = "flag_art.txt"
with open(output_art_file, "w", encoding="utf-8") as f:
    for r in ascii_art:
        # Nhân đôi chiều rộng để bù trừ tỷ lệ khung hình
        readable_row = r.replace('0', '  ').replace('1', '██')
        f.write(readable_row + "\n")

print("\n" + "="*60)
print(f" Đã xuất bức ảnh ASCII Art ra file: {output_art_file}")