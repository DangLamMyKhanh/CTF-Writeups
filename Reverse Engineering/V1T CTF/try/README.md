# [V1T CTF 2026] Reverse Engineering

## THÔNG TIN BÀI CHALLENGE
- Category: Reverse Engineering
- Target File: chall.exe
- File Type: PE32+ executable (64-bit Windows console applicaiton)
- Difficulty:
- Architecture:
  - Section Spoofing: Ngụy trang cấu trúc file PE bằng cách nhét 28 phân vùng rác giả mạo các công cụ bảo vệ nổi tiếng như VMProtect, Enigma, UPX... để đánh lừa các công cụ phân tích tự động.
  - Anti-Analysis (Debug/VM/Timing): Sử dụng các API kiểm tra luồng gỡ lỗi (`IsDebuggerPresent`, `CheckRemoteDebuggerPresent`) kết hợp với kiểm tra độ trễ thời gian hệ thống (`QueryPerformanceCounter` & `Sleep`) nhằm phát hiện môi trường ảo hóa hoặc hành vi trace lệnh của phân tích viên.
  - SMC (Self-Modifying Code) / Custom VM: Giải mã động một phân vùng mã hóa 365 byte (`DAT_004043a8`) khi đang chạy. Khối dữ liệu này thực chất là một chuỗi Bytecode tùy biến. Chương trình chính hoạt động như một Trình thông dịch Máy ảo (VM Interpreter) để thực thi tuần tự các chỉ thị ảo này nhằm kiểm tra tính đúng đắn của Flag.

## CÔNG CỤ SỬ DỤNG
- CLI Tools: file, strings (Sơ bộ và phân tích tĩnh)
- Ghidra: Phân tích tĩnh và đọc mã giả (Decompiled code).
- Python: Viết kịch bản phụ trợ để giải quyết bài toán (`decrypt_payload.py` và `disasm_vm.py`)
- Máy ảo Windows 10: Môi trường thực thi động

## QUÁ TRÌNH PHÂN TÍCH
### Bước 1: Phân tích tĩnh (Static Analysis)
**A. Đánh giá sơ bộ cấu trúc PE**
Kiểm tra thông tin file bằng lệnh `file`;
```bash
$ file chall.exe
chall.exe: PE32+ executable (console) x86-64 (stripped to external PDB), for MS Windows, 28 sections
```
Mặc dù chương trình chứa tới 28 sections, chúng ta vẫn có thể mở và decompile trực tiếp các hàm nguyên bản bằng Ghidra mà không gặp trở ngại lớn. Điều này chứng minh đây là kỹ thuật Section Spoofing nhằm dọa phân tích viên từ bỏ ý định dịch ngược tĩnh.
**B. Phân tích hàm Entry & Main (FUN_00402962)**
Hàm khởi tạo `entry` nhảy trực tiếp vào hàm thực thi chính tại địa chỉ `FUN_00402962`:
```C
undefined8 FUN_00402962(void)
{
    ...
    FUN_0040276f(&local_88);  // Trim timeline
    uVar4 = FUN_004024d9();  // Lấy trạng thái hệ thống (Anti-Debug/VM)
    cVar1 = FUN_00402618(&local_88,(byte)uVar4);  // hàm kiểm tra Flag sinh tử
    FUN_00401f09(&local_88,0x80);
    if (cVar1 == '\0') {
      printf(s_%s[-]_rejected%s_004046dd,PTR_DAT_00404560,PTR_DAT_00404520);
      uVar4 = 1;
    }
    else {
      printf(s_%s[+]_accepted%s_004046ca,PTR_DAT_00404550,PTR_DAT_00404520);
      uVar4 = 0;
    }
  }
  return uVar4;
}
```
**C. Phân tích bẫy Môi trường (`FUN_004024d9`)**
Hàm này chịu trách nhiệm sinh ra biến trạng thái `param_2` đ1ong vai trò làm Khóa Giải mã cho các lớp phía sau:
- Nếu phát hiện debugger trực tiếp (`IsDebuggerPresent`): Trả về `0x13`
- Nếu phát hiện remote debugger (`CheckRemoteDebuggerPresent`): Trả về `0x29`
- Nếu phát hiện môi trường ảo hóa VM hoặc phân tích viên trace lệnh quá chậm bằng phép đo sai lệch thời gian hệ thống:
```C
    if ((BVar1 != 0) && (BVar1 = QueryPerformanceCounter(&local_28), BVar1 != 0)) {
      Sleep(0xc);  // Ngủ 12ms
      QueryPerformanceCounter(&local_30);
      lVar3 = (local_30.QuadPart - (longlong)local_28) * 1000;
      if (lVar3 + local_20.QuadPart * -600 != 0 && local_20.QuadPart * 600 <= lVar3) {
        return 0x4e;   // VM/Lag detecred -> trả về 0x4e
      }  
    }
```
*(Nếu thời gian thực tế thực thi lệnh Sleep(12ms) vượt quá 600ms, bẫy sẽ bị kích hoạt)*
- Nếu môi trường sạch (Normal Execution): Trả về `0xa7`.
<br>

**D. Phân tích hàm giải mã động (`FUN_00401fb8`)**
- Hàm kiểm tra sinh tử `FUN_00402618` gọi tới `FUN_00401fb8` để giải mã khối dữ liệu tĩnh 365 byte tại địa chỉ `DAT_004043a8`.
<br>

- Hàm băm trộn khóa giải mã mix (`FUN_0040199f`) và thuật toán giải mã xoay bit phải ror8 (`FUN_004018ed`) được định nghĩa tuần tự trong file thực thi. Nếu người dùng nhập sai Flag hoặc môi trường bị dính bẫy gỡ lỗi, khối 365 byte này sẽ giải mã ra mã máy rác khiến hệ phương trình băm phía sau bị vô nghiệm (`UNSAT`).


### Bước 2: Phân tích động (dynamic Analysis)
Tiến hành cô lập bẫy giải mã động bằng cách viết script Python mô phỏng chính xác thuật toán giải mã của hàm `FUN_00401a3f` trên khối dữ liệu thô `DAT_004043a8`.
<br>

Do file chạy bình thường trong môi trường thật, chúng ta chọn khóa gỡ lỗi mặc định là `0xa7` để thực hiện giải mã. Bytecode giải mã thu được có kích thước 365 byte, hoàn toàn không chứa bất kỳ chuỗi Flag dạng plaintext nào.
<br>

Nạp file bytecode đã giải mã vào Ghidra và tiến hành Disassemble, phân tích cấu trúc mã máy ảo tại hàm thông dịch `FUN_00401fb8` (vùng mã máy bị gài bẫy gối lệnh khiến Decompiler của Ghidra bị lỗi).

### Bước 3: Quá trình Khai thác (Exploitation)
Khi dịch ngược hoàn chỉnh các lệnh Assembly của hàm thông dịch máy ảo `FUN_00401fb8`, phát hiện cấu trúc tập lệnh gọn gàng của Máy ảo:
```Assembly
00402470   MOVZX  EAX, byte ptr [RBP + local_19]  ; EAX = Opcode giải mã động tiếp theo
00402474   CMP    EAX, 0x71
...
0040248f   CMP    EAX, 0x32  ; Opcode 0x32 -> Jump tới ADD
00402498   CMP    EAX, 0x4b  ; Opcode 0x4b -> Jump tới LOAD_FLAG
```
**Phân tích hệ thống chỉ thị (Opcodes):**
1. Opcode `0x4b` (`LOAD_FLAG [idx]`): Đọc ký tự tiếp theo trong bytecode làm chỉ mục `idx` và gán: `REG_B = Flag[idx]`.
2. Opcode `0x32` (`ADD [val]`): Thực hiện cộng dồn: `REG_B = (REG_B + val) & 0xff`.
3. Opcode `0x18` (`ROL [val]`): Thực hiện xoay trái bit 8-bit: `REG_B = ROL8(REG_B, val & 7)`.
4. Opcode `0x71` (`XOR [val]`): Thực hiện phép toán logic: `REG_B = REG_B ^ val`.
5. Opcode `0xd4` (`ASSERT [expected]`): Thực hiện kiểm tra: `status |= (REG_B ^ expected)`.

**Phương pháp bẻ gãy máy ảo**
Mặc dù chương trình có chứa chỉ thị 0xa9 thực hiện kiểm tra chéo (cross-check) phức tạp giữa các ký tự, nhưng quan sát toàn bộ bytecode cho thấy: Mỗi ký tự từ vị trí 0 đến 21 của Flag đều có một chuỗi kiểm tra độc lập tuyến tính dạng:
`LOAD_FLAG [idx] -> XOR [val1] -> ADD [val2] -> ROL [val3] -> XOR [val4] -> ASSERT [expected]`
Do đó, chúng ta có thể đảo ngược toán học trực tiếp từng ký tự một theo công thức:
$$temp = expected \oplus val4$$

$$temp = ROR8(temp, val3)$$

$$temp = (temp - val2) \pmod{256}$$

$$Flag[idx] = temp \oplus val1$$
Điều này cho phép giải quyết 100% Flag của bài toán mà không cần quan tâm đến các hàm kiểm tra chéo phức tạp khác.

### Bước 4: Script
Kịch bản Python khai thác hoàn chỉnh giúp tự động bóc tách tham số trực tiếp từ file bytecode decrypted_real_0xa7.bin và giải ngược ra Flag chính xác: 
(File `solver.py` đính kèm)

## KẾT QUẢ:
Flag: v1t{n0_dump_just_pain}

## BÀI HỌC RÚT RA
- **Vượt qua bẫy Anti-Analysis bằng phân tích tĩnh:** Gặp các cơ chế bẫy anti-debugging/timing gài bẫy thay đổi luồng thực thi động, phương pháp phân tích tĩnh và mô phỏng toán học là lựa chọn tối ưu và an toàn nhất.
- **Kỹ thuật giải ngược hệ phương trình Máy ảo:** Khi đối đầu với máy ảo (VM), việc phân tích và hiểu rõ tác dụng của từng Opcode là chìa khóa. Trong nhiều trường hợp, việc phát hiện tính chất độc lập, over-determined của các phương trình giúp chúng ta giải trực tiếp Flag mà không cần đảo ngược toàn bộ cấu trúc kiểm tra phức tạp.
- **Tránh bẫy ngụy trang phân vùng (Section Spoofing):** Không vội nản chí khi thấy tệp tin PE chứa nhiều phân vùng giả mạo các công cụ bảo vệ nặng nề. Hãy luôn thử phân tích cú pháp của tệp bằng công cụ dịch ngược (như Ghidra/IDA Pro) trước để xác minh độ chân thực của cấu trúc file.

---
Author: Dang Lam My Khanh