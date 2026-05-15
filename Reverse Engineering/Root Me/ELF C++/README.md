# [Root-Me] Cracking: ELF C++ - 0 Protection

## THÔNG TIN BÀI CHALLENGE
- Category: Cracking 
- Target File: ch25.bin
- Architecture: ELF 32-bit LSB (Intel 80386)
- Language: C++
- Difficulty: Very Easy
- Mục tiêu: Phân tích logic sinh password và thực hiện trích xuất password từ bộ nhớ lúc runtime.

## CÔNG CỤ SỬ DỤNG
- CLI Tools: file, strings (Sơ bộ và phân tích tĩnh)
- Ghidra: Phân tích tĩnh và đọc mã giả (Decompiled code).
- GDB: Phân tích động, đặt breakpoint và kiểm tra bộ nhớ (Memory inspection).

## QUÁ TRÌNH PHÂN TÍCH
### Bước 1: Kiểm tra sơ bộ (Reconnaissance)
Sử dụng lệnh file để xác định định dạng tệp tin:
```bash
$ file ch25.bin
ch25.bin: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=38a418f97a019e3a6108932d4a7196637e368a88, not stripped
```
Nhận định:
- `not stripped`: File còn giữ nguyên symbol table, giúp việc phân tích dễ dàng hơn vì tên hàm (`main`, `plouf`) được giữ nguyên.
- Khi sử dụng lệnh `strings`, ta nhận diện được các chuỗi thông báo thành công và thất bại. Tuy nhiên, mật khẩu đúng không xuất hiện dưới dạng Plaintext. Điều này xác nhận chương trình sử dụng cơ chế Runtime Password Generation.

### Bước 2: Phân tích tĩnh (Static Analysis)
SỬ dụng Ghidra để xem xét hàm `main`:
```C++
undefined4 main(int param_1,undefined4 *param_2)

{
  char *pcVar1;
  bool bVar2;
  ostream *poVar3;
  undefined4 uVar4;
  allocator local_1e;
  allocator local_1d;
  string local_1c [4];
  string local_18 [4];
  string local_14 [4];
  undefined4 *local_10;
  
  local_10 = &param_1;
  if (param_1 < 2) {
    pcVar1 = (char *)*param_2;
    poVar3 = std::operator<<((ostream *)std::cerr,"usage : ");
    poVar3 = std::operator<<(poVar3,pcVar1);
    poVar3 = std::operator<<(poVar3," password");
    std::ostream::operator<<(poVar3,std::endl<>);
    uVar4 = 5;
  }
  else {
    std::allocator<char>::allocator();
                    /* try { // try from 08048b0e to 08048b12 has its CatchHandler @ 08048c64 */
    std::string::string(local_14,&DAT_08048dc4,&local_1d);
    std::allocator<char>::allocator();
                    /* try { // try from 08048b33 to 08048b37 has its CatchHandler @ 08048c3b */
    std::string::string(local_18,&DAT_08048dcc,&local_1e);
                    /* try { // try from 08048b4c to 08048b50 has its CatchHandler @ 08048c1d */
    plouf(local_1c,local_18,local_14);
                    /* try { // try from 08048b5a to 08048b5e has its CatchHandler @ 08048c2c */
    std::string::~string(local_18);
    std::allocator<char>::~allocator((allocator<char> *)&local_1e);
                    /* try { // try from 08048b70 to 08048b74 has its CatchHandler @ 08048c55 */
    std::string::~string(local_14);
    std::allocator<char>::~allocator((allocator<char> *)&local_1d);
                    /* try { // try from 08048b92 to 08048c08 has its CatchHandler @ 08048c7b */
    bVar2 = std::operator==(local_1c,(char *)param_2[1]);
    if (bVar2) {
      poVar3 = std::operator<<((ostream *)std::cout,
                               "Bravo, tu peux valider en utilisant ce mot de passe...");
      std::ostream::operator<<(poVar3,std::endl<>);
      poVar3 = std::operator<<((ostream *)std::cout,
                               "Congratz. You can validate with this password...");
      std::ostream::operator<<(poVar3,std::endl<>);
    }
    else {
      poVar3 = std::operator<<((ostream *)std::cout,"Password incorrect.");
      std::ostream::operator<<(poVar3,std::endl<>);
    }
    uVar4 = 0;
    std::string::~string(local_1c);
  }
  return uVar4;
}
```
Trong hàm `main`, chúng ta tập trung vào đoạn logic xử lý chính:
1. **Khởi tạo đối tượng:** Chương trình khởi tạo các đối tượng `std::string (local_14, local_18)`.
2. **Dữ liệu gốc:** Hai chuỗi bí mật được nạp từ vùng dữ liệu (`DAT_08048dc4` và `DAT_08048dcc`).
3. **Hàm biến đổi:**
   ```C++
   plouf(local_1c, local_18, local_14);
   ```
   Hàm `plouf` nhận vào hai chuỗi gốc và thực hiện các phép toán (có thể là XOR, nối chuỗi hoặc biến đổi ký tự) để tạo ra password cuối cùng và lưu vào `local_1c`.

4. **So sánh:**
   ```C++
   bVar2 = std::operator==(local_1c, (char *)param_2[1]);
   ```
   Chương trình so sánh `local_1c` (password đúng) với `argv[1]` (input của người dùng).

**Nhận định:** Thay vì ngồi dịch ngược thuật toán phức tạp bên trong hàm `plouf`, ta có thể đứng đợi ở lệnh `std::operator==` và xem giá trị của `local_1c`.

### Bước 3: Xác minh động (Dynamic Analysis) với GDB
Đây là bước quan trọng nhất để lấy Flag mà không cần hiểu thuật toán sinh mã.
1. **Đặt Breakpoint:** Tìm địa chỉ của lệnh gọi hàm so sánh trong Ghidra (`0x08048b92`).
2. **Thực thi:** Chạy chương trình với tham số giả: `gdb ./ch25.bin` -> `b*0x08048b92` -> `r AAAA`.
3. **Kiểm tra Stack (x86 32-bit):**
 - Trong kiến trúc 32-bit, các tham số hàm được đẩy vào Stack.
 - Sử dụng `x/4wx $esp` để xem các con trỏ trên đỉnh Stack.
 - Kết quả cho thấy tham số thứ nhất trỏ tới một vùng nhớ chứa địa chỉ của chuỗi Flag.
    ```gdb
   (gdb) x/4wx $esp
   0xffffce00:	0xffffce14	0xffffd0f9	0xffffce1c	0xf7ce6440
   ```
   Phân tích các giá trị trên Stack:
   | Địa chỉ Stack | Giá trị (Dữ liệu) | Ý nghĩa |
   | :--- | :---: | :--- |
   | `0xffffce00` | `0xffffce14` | **Tham số 1:** Địa chỉ của đối tượng `std::string` chứa mật khẩu đúng (kết quả từ hàm `plouf`). |
   | `0xffffce04` | `0xffffd0f9` | **Tham số 2:** Địa chỉ của chuỗi ký tự người dùng nhập vào (trong trường hợp này là "AAAA"). |
   | `0xffffce08` | `0xffffce1c` | Dữ liệu rác hoặc biến cục bộ khác trên Stack. |
   | `0xffffce0c` | `0xf7ce6440` | Địa chỉ trả về (Return Address) sau khi kết thúc hàm. |

**Tại sao ta xác định được như vậy?**
1. Theo **Calling Convention** của x86, khi gọi một hàm so sánh chuỗi như `operator==(str_a, str_b)`, hai tham số `str_a` và `str_b` sẽ nằm ngay trên đỉnh Stack.
2. Kiểm tra thực tế tham số thứ 2 tại `0xffffd0f9`:
   ```gdb
   (gdb) x/s 0xffffd0f9
   0xffffd0f9: "AAAA"
   ```
   Vì `0xffffd0f9` chứa chuỗi "AAAA" tôi đã nhập, suy ra giá trị còn lại `0xffffce14` chính là địa chỉ dẫn đến mật khẩu cần tìm.

**Truy xuất mật khẩu cuối cùng:**
<br>
Do tệp tin được biên dịch từ mã nguồn C++, kiểu dữ liệu `std::string` được sử dụng thay cho `char*` truyền thống. Qua quan sát bộ nhớ tại `0xffffce14` (địa chỉ của đối tượng trên Stack), ta thấy 4 byte đầu tiên không chứa các ký tự ASCII hợp lệ mà chứa một địa chỉ vùng nhớ khác (0x0804f4cc). Điều này chứng tỏ `std::string` đang lưu trữ nội dung mật khẩu tại vùng nhớ Heap hoặc Data segment để quản lý động, và tại Stack chỉ lưu trữ con trỏ dẫn tới vùng nhớ đó.
<br>
Sử dụng kỹ thuật giải tham chiếu (dereferencing) để lấy chuỗi:
```gdb
(gdb) x/s *(char**)0xffffce14
0x804f4cc: "Here_you_have_to_understand_a_little_C++_stuffs"
```
Kết quả trả về chính là mật khẩu của bài challenge.

## KẾT QUẢ
Flag: Here_you_have_to_understand_a_little_C++_stuffs

## BÀI HỌC RÚT RA
- **C++ Reverse Engineering:** Các đối tượng std::string trong C++ không lưu chuỗi trực tiếp mà thường thông qua một con trỏ. Khi debug, cần tìm lớp con trỏ cuối cùng để thấy dữ liệu thật.
- **Black-box Testing:** Nếu thuật toán biến đổi (plouf) quá rắc rối, hãy tập trung vào điểm cuối cùng (lệnh so sánh) để lấy kết quả đầu ra.
- **32-bit Calling Convention:** Hiểu cách tham số được truyền qua Stack trong x86 là chìa khóa để xác định dữ liệu trong GDB.

---
Author: Dang Lam My Khanh