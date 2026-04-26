# [Root-Me] Cracking: ELF x86 - Basic

## THÔNG TIN BÀI CHALLENGE
- Category: Cracking
- Target file: ch2.bin
- Architecture: ELF 32-bit LSB (Intel 80386)
- Difficulty: Very Easy
- Mục tiêu: Phân tích tệp tin biên dịch tĩnh (Statically Linked) để tìm logic xác thực đa lớp (Username/Password), từ đó trích xuất Flag.

## CÔNG CỤ SỬ DỤNG
- CLI Tools: file, stirngs
- Statically Analysis: Ghidra
- Environment: Linux x86_64 với gói tương thích libc6:i386
 
## QUÁ TRÌNH PHÂN TÍCH
### Bước 1: Kiểm tra sơ bộ (Reconnaissance)
- Sử dụng lệnh file để xác định định dạng tệp tin:
```bash
$ file ch2.bin
ch2.bin: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, for GNU/Linux 2.6.8, with debug_info, not stripped
```
**Nhận định:**
<br>
**statically linked**: Điểm khác biệt so với bài trước. Tất cả thư viện (như lib) đã được nhúng vào file. Điều này khiến kích thước file tăng đáng kể và làm các công cụ như ltrace mất tác dụng vì không còn Shared Library Calls.
<br>
**not stripped, with debug_info**: file vẫn giữ lại bảng kí hiệu và thông tin debug. Đây là 'lỗ hổng' lớn nhất giúp Reverser định vị các hàm quan trọng nhanh chóng.

- Khi chạy lệnh strings, kết quả trả về hàng ngàn dòng (do chứa code của libc).
```bash
$ strings ch2.bin
```
Xem xét sơ bộ phát hiện đoạn code sau:
 ```bash
...
Allocating memory
Reallocating memory
john
the ripper
############################################################
##        Bienvennue dans ce challenge de cracking        ##
############################################################
username: 
password: 
987654321
Bien joue, vous pouvez valider l'epreuve avec le mot de passe : %s !
Bad password
Bad username
...
```
Giả thuyết đặt ra "john" - "the ripper" là cặp Username - Password được hardcoded.

## Bước 2: Phân tích tĩnh (Static Analysis)
- Locating main function:
Trong các tệp tin Statically Linked, số lượng hàm có thể lên tới hàng trăm. Tuy nhiên, nhờ vào việc file not stripped, sử dụng Ghidra để định vị hàm main một cách dễ dàng thông qua Symbol Tree.
- Logic decompilation (giải mã logic):
```C
undefined4 main(void)

{
  char *pcVar1;
  int iVar2;
  undefined4 local_10;
  
  puts("############################################################");
  puts("##        Bienvennue dans ce challenge de cracking        ##");
  puts("############################################################\n");
  printf("username: ");
  pcVar1 = (char *)getString(local_10);
  iVar2 = strcmp(pcVar1,"john");
  if (iVar2 == 0) {
    printf("password: ");
    pcVar1 = (char *)getString(pcVar1);
    iVar2 = strcmp(pcVar1,"the ripper");
    if (iVar2 == 0) {
      printf("Bien joue, vous pouvez valider l\'epreuve avec le mot de passe : %s !\n","987654321");
    }
    else {
      puts("Bad password");
    }
  }
  else {
    puts("Bad username");
  }
  return 0;
}
```
**Phân tích thuật toán:**
1. Chương trình thực hiện xác thực 2 vòng (Nested If-statement).
2. Hàm strcmp được sử dụng là phiên bản nội bộ (internal version) được nhúng sẵn trong binary.
3. Flag thực sự (987654321) cũng được lưu trữ dưới dạng plaintext và chỉ được in ra khi cả 2 điều kiện cùng thỏa mãn.

## Bước 3: Xác minh động (Dynamic Verification):
Mặc dù ltrace không thể can thiệp vào các hàm nội bộ của file Static, ta vẫn có thể sử dụng GDB để kiểm tra bộ nhớ nếu cần thiết. Tuy nhiên, với logic đơn giản đã tìm thấy, việc thực thi trực tiếp là phương pháp nhanh nhất:
```bash
$ ./ch2.bin
username: john
password: the ripper
Bien joue, vous pouvez valider l'epreuve avec le mot de passe : 987654321
```
## KẾT QUẢ
Flag: 987654321

# BÀI HỌC RÚT RA:
1. Harcoded Credentials: Việc lưu trữ Username/Password/Flag dưới dạng Plaintext trong tệp binary là 1 sai lầm nghiêm trọng. Bất kì ai có thể truy cập file đều có thể dùng strings để trích xuất dữ liệu.
2. Binary Stripping: Việc không strip binary giúp kể tấn công tiết kiệm thời gian phân tích vì tên hàm và cấu túc dữ liệu bị lộ hoàn toàn.
3. Static Linking Security: Mặc dù Static Linking làm khó các công cụ phân tích nhanh như ltrace, nhưng nó lại cung cấp cho Reverser mọi thứ họ cần trong một file duy nhất, không phụ thuộc vào môi trường hệ thống.
<br>
Khuyến nghị: Cần Hash mật khẩu (bcrypt/argon2) và thực hiện Strip binary trước khi phát hành (Release).

---
Author: Dang Lam My Khanh