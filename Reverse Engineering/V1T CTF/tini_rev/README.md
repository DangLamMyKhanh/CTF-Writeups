# [V1T CTF 2026] Reverse Engineering

## THÔNG TIN BÀI CHALLENGE
- Category: Reverse Engineering
- Target File: tini_rev
- File Type: ELF 64-bit static executable, x86-64
- Difficulty:
- Architecture:
  - Tiny ELF & Corrupted SHT: File có kích thước siêu nhỏ (chỉ 904 byte). Tác giả xóa bỏ hoàn toàn bảng phân vùng Section Header Table (SHT) để giảm dung lượng file xuống dưới 1KB, làm cho các công cụ disassembly tiêu chuẩn như objdump báo lỗi file format not recognized.
  - Key-dependent RLE Decompression: Chương trình đọc Flag của người dùng, cộng dồn mã ASCII của Flag để tạo ra khóa giải mã KEY. Khóa này được dùng để giải mã một khối dữ liệu tĩnh 227 words (`0x4001b8`). Khối dữ liệu sau khi giải mã chính là các độ dài nén (run lengths) của thuật toán nén ảnh RLE (Run-Length Encoding). Nếu nhập đúng Flag, chương trình sẽ giải nén và in ra bức ảnh ASCII Art chứa Flag ra màn hình.

## CÔNG CỤ SỬ DỤNG
- CLI Tools: file, strings (Sơ bộ và phân tích tĩnh)
- Ghidra: Phân tích tĩnh và đọc mã giả (Decompiled code).
- Python: Viết kịch bản phụ trợ để giải quyết bài toán

## QUÁ TRÌNH PHÂN TÍCH
### Bước 1: Phân tích tĩnh (Static Analysis)
**A. Đánh giá sơ bộ cấu trúc**

Kiểm tra thông tin file bằng lệnh `file`:
```bash
$ file tini_rev
tini_rev: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, corrupted section header size
```
Kiểm tra kích thước file, ta thấy kích thước file nhỏ, 904 bytes. Do Section Header bị hỏng, ta ép Ghidra nạp file dưới dạng Raw Binary hoặc cho trình nạp ELF tự động tìm Program Header. Trình nạp của Ghidra hoạt động giống Loader của nhân Linux, bỏ qua SHT lỗi và nạp thành công các phân vùng mã máy vào địa chỉ gốc `0x400000`, tự động định vị được Entry Point (_start) tại địa chỉ `0x00400070`.

**B. Dọn mã giả rác trong Ghidra**
- Do không có ranh giới phân vùng chuẩn, Ghidra cố gắng disassemble toàn bộ dữ liệu tĩnh bắt đầu từ `0x4001b8` thành mã máy, tạo ra một khối lượng khổng lồ mã giả rác chứa lệnh gãy halt_baddata().
- Thực tế, luồng thực thi chuẩn của chương trình ngắn nằm từ địa chỉ `0x00400070` đến lệnh gọi hệ thống thoát sys_exit tại `0x004001b6`.

### Bước 2: Phân tích động (dynamic Analysis)
Dịch ngược luồng Assembly thực tế tại điểm khởi chạy `0x00400070`:
1. Nhận đầu vào từ bàn phím:
    ```assembly
    00400083 31 c0           XOR        EAX,EAX     ; sys_read
    00400085 31 ff           XOR        EDI,EDI     ; stdin
    00400087 4c 89 c6        MOV        RSI,R8      ; R8 = RSP + 0x6200 (Vùng nhớ nhập Flag)
    0040008a ba 00 01        MOV        EDX,0x100   ; 256 bytes
             00 00
    0040008f 0f 05           SYSCALL
    ```
2. Tính toán khóa giải mã mật mã:
    ```assembly
                     LAB_0040009e     XREF[1]:     004000ac(j)  
        0040009e ac              LODSB      RSI      ; AL = ký tự Flag vừa nhập
        0040009f 3c 0a           CMP        AL,0xa   ; Bỏ qua '\n'
        004000a1 74 09           JZ         LAB_004000ac
        004000a3 3c 0d           CMP        AL,0xd   ; Bỏ qua '\r'
        004000a5 74 05           JZ         LAB_004000ac
        004000a7 0f b6 d0        MOVZX      EDX,AL
        004000aa 01 d5           ADD        EBP,EDX  ; EBP += AL (Cộng dồn mã ASCII!)
    ```
    Khóa giải mã `KEY` thực chất là Tổng giá trị mã ASCII của Flag.

3. Giải mã RLE Meatadata:
    ```assembly
                    LAB_004000c8       XREF[1]:     004000d3(j)  
        004000c8 0f b7 06        MOVZX      EAX,word ptr [RSI]   =>LAB_004001b8     ; Đọc dữ liệu nén tĩnh tại 0x4001b8
        004000cb 48 83 c6 02     ADD        RSI,0x2
        004000cf 29 e8           SUB        EAX,EBP     ; Giải mã: decrypted = encrypted - KEY
        004000d1 66 ab           STOSW      RDI
    ```
4. Giải nén hình ảnh RLE:

    Máy ảo chạy vòng lặp ngoài 10 lần (tương ứng với 10 dòng của bức ảnh). Mỗi dòng có độ rộng cố định là 140 ký tự (MOV R10D, 0x8c). Nó đọc các giá trị run-length đã giải mã và lặp lại việc tô ký tự '0' hoặc '1' tương ứng ra màn hình.

### Bước 3: Script
- Vì tổng mã ASCII của Flag (`KEY`) là một số nguyên nhỏ (thường dao động trong khoảng 400 đến 1500), chúng ta có thể viết một kịch bản Python tự động mô phỏng máy ảo, thử mọi khóa `KEY` khả thi.
- Khóa `KEY` chuẩn xác sẽ giải mã ra các run-length hợp lệ (tổng của mỗi dòng phải nhỏ hơn hoặc bằng 140).
(File `tini_rev.py` đính kèm)
- Mở file `flag_art.txt` và thu nhỏ lại khoảng 40%, chúng ta sẽ nhìn thấy bức ảnh hiển thị rõ ràng chuỗi ký tự vẽ khối đậm: v1t{^}.
- Xác thực toán học:
     `118(′v′) + 49(′1′) + 116(′t′) + 123(′{′) + 94(′^′) + 125(′}′) = 625`
     (Trùng khớp với giá trị KEY giải nén hình ảnh)

## KẾT QUẢ:
Flag: v1t{^}

## BÀI HỌC RÚT RA
- **Hiểu rõ trình nạp ELF của Linux:** Trong thực tế, hệ điều hành chỉ quan tâm đến Program Headers để thực thi chương trình. Việc làm hỏng hoặc xóa bỏ Section Headers là phương pháp chống phân tích tĩnh bằng công cụ dòng lệnh phổ biến nhưng có thể dễ dàng vượt qua bằng Ghidra hoặc IDA Pro.
- **Aspect Ratio trong ASCII Art:** Khi xử lý các thử thách sinh ảnh ASCII, hãy luôn nhớ nhân đôi chiều rộng của mỗi ký tự khối (██) để bù đắp cho chiều cao gấp đôi của font chữ Terminal mặc định, giúp việc nhận diện chữ bằng mắt thường dễ dàng hơn gấp nhiều lần.

---
Author: Dang Lam My Khanh