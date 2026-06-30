# Đọc tệp bytecode đã giải mã của khóa 0xa7
filename = "decrypted_real_0xa7.bin"
try:
    with open(filename, "rb") as f:
        bytecode = f.read()
except FileNotFoundError:
    print(f"[x] Không tìm thấy file {filename}!")
    exit()

def ror8(val, shift):
    shift &= 7
    if shift != 0:
        val = ((val >> shift) | (val << (8 - shift))) & 0xFF
    return val & 0xFF

flag = [None] * 22
pc = 0

print("[*] Đang tự động phân tích bytecode và giải ngược hệ phương trình...")

while pc < len(bytecode):
    opcode = bytecode[pc]
    if opcode == 0:
        if all(b == 0 for b in bytecode[pc:]):
            break
            
    pc += 1
    
    # Tìm kiếm cấu trúc kiểm tra ký tự độc lập:
    # 0x4b (idx) -> 0x71 (xor1) -> 0x32 (add1) -> 0x18 (rol_val) -> 0x71 (xor2) -> 0xd4 (expected)
    if opcode == 0x4b:
        idx = bytecode[pc]
        pc += 1
        
        # Kiểm tra xem có khớp các lệnh tiếp theo không
        if (pc + 10 < len(bytecode) and 
            bytecode[pc] == 0x71 and 
            bytecode[pc+2] == 0x32 and 
            bytecode[pc+4] == 0x18 and 
            bytecode[pc+6] == 0x71 and 
            bytecode[pc+8] == 0xd4):
            
            xor1 = bytecode[pc+1]
            add1 = bytecode[pc+3]
            rol_val = bytecode[pc+5] & 7
            xor2 = bytecode[pc+7]
            expected = bytecode[pc+9]
            
            # Tiến hành giải ngược toán học
            temp = expected ^ xor2
            temp = ror8(temp, rol_val) # Ngược của ROL là ROR
            temp = (temp - add1) & 0xFF
            flag_char = temp ^ xor1
            
            flag[idx] = chr(flag_char)
            # print(f"    [+] Tìm thấy Flag[{idx:02d}] = '{chr(flag_char)}'")
            
            pc += 10 # Nhảy qua các lệnh đã xử lý
            
    elif opcode == 0x5d:
        pc += 1
    elif opcode == 0xa9:
        pc += 4
    elif opcode == 0xee:
        pc += 1

real_flag = "".join(f if f is not None else '?' for f in flag)
print("\n" + "="*50)
print(f"FLAG CỦA BÀI TOÁN:\n\n    {real_flag}")
print("="*50)