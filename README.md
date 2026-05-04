# CVE-2026-31431 Smart Check Script

## Tổng quan

Script tự động phát hiện và xử lý lỗ hổng **CVE-2026-31431** — một lỗ hổng liên quan đến module kernel `algif_aead` (AF_ALG AEAD interface) trên các hệ thống Linux chạy kernel **>= 4.10**.

(Created by TonyCao)

## CVE-2026-31431 là gì?

`algif_aead` là module kernel cung cấp giao diện AEAD (Authenticated Encryption with Associated Data) qua AF_ALG socket. Lỗ hổng cho phép kẻ tấn công cục bộ khai thác race condition trong quá trình gửi/nhận dữ liệu qua socket AF_ALG, dẫn đến **privilege escalation** (leo thang đặc quyền).

- **Phạm vi ảnh hưởng:** Kernel Linux >= 4.10
- **Điều kiện khai thác:** Module `algif_aead` phải được nạp (loaded) — hoặc attacker có quyền nạp module
- **Mức độ nghiêm trọng:** CVSS 7.8 (HIGH) — Local Privilege Escalation
- **Cách khắc phục:** Chặn (blacklist) module `algif_aead`, không cho phép nạp tự động hoặc thủ công

## Cách thức hoạt động của script

### Sơ đồ luồng quyết định

```
                  +-----------------------+
                  |  Kiểm tra quyền root  |
                  +-----------+-----------+
                              |
                  +-----------v-----------+
                  | Parse kernel version  |
                  | (uname -r)            |
                  +-----------+-----------+
                              |
                  +-----------v---------------------------+
                  |  Kernel >= 4.10 ?                     |
                  +--+--------------------------------+---+
                     |                                |
                    NO                               YES
                     |                                |
           +---------v---------+          +-----------v-----------+
           | [SAFE]             |          | /etc/modprobe.d/      |
           | Kernel không bị    |          | cve-2026-31431.conf   |
           | ảnh hưởng          |          | tồn tại?              |
           | exit 0             |          +--+----------------+---+
           +--------------------+             |                |
                                             NO              YES
                                              |                |
                              +---------------v---+    +-------v----------+
                              | lsmod có          |    | [INFO]           |
                              | algif_aead?       |    | Đã được hardening|
                              +--+-------------+--+    | exit 0           |
                                 |             |       +------------------+
                                NO            YES
                                 |              |
                      +----------v--+   +-------v----------+
                      | [OK]        |   | [CRITICAL]       |
                      | Module không|   | Module đang chạy |
                      | được nạp    |   | + kernel lỗi     |
                      | exit 1      |   | exit 2           |
                      +-------------+   +-------+----------+
                                                |
                              +-----------------v-----------------+
                              |  Flag đang dùng?                  |
                              +--+-----------+--------+--------+--+
                                 |           |        |        |
                            --check     --scan     --fix  (không flag)
                                 |           |        |        |
                           In kết quả   Hỏi xác    Tự động  Hiển thị
                           + exit 2     nhận rồi   sửa +    hướng dẫn
                                        sửa        exit 0
```

### Các bước kiểm tra chi tiết

| Bước | Hàm                        | Mô tả                                                                         |
| ---- | -------------------------- | ----------------------------------------------------------------------------- |
| 1    | `require_root`             | Kiểm tra UID = 0, nếu không thì exit 3                                        |
| 2    | `parse_kernel`             | Trích xuất major.minor từ `uname -r`, dùng `LC_ALL=C sed` để tránh lỗi locale |
| 3    | `is_vuln_kernel`           | So sánh: major > 4 hoặc (major = 4 và minor >= 10)                            |
| 4    | `is_hardened`              | Kiểm tra file `/etc/modprobe.d/cve-2026-31431.conf` đã tồn tại chưa           |
| 5    | `is_module_loaded`         | Dùng `lsmod \| grep -qw algif_aead`                                           |
| 6    | `print_status`             | In kết quả theo 4 cấp, trả về exit code tương ứng                             |
| 7    | `prompt_fix` / `apply_fix` | Tương tác hoặc tự động hardening                                              |

### Cơ chế hardening

Khi áp dụng bản vá, script thực hiện 3 hành động:

1. **Tạo file cấu hình modprobe** tại `/etc/modprobe.d/cve-2026-31431.conf`:

   ```
   install algif_aead /bin/false
   blacklist algif_aead
   ```

   - `install algif_aead /bin/false` — mỗi khi có lệnh yêu cầu nạp module, kernel sẽ chạy `/bin/false` thay vì nạp thật, khiến thao tác luôn thất bại
   - `blacklist algif_aead` — ngăn `udev` và các tool tự động nạp module

2. **Gỡ module khỏi memory** — `modprobe -r algif_aead` (bỏ qua lỗi nếu module không được nạp)

3. **Rebuild initramfs** — để đảm bảo module không bị nạp sớm trong quá trình boot:
   - Ubuntu/Debian: `update-initramfs -u -k <kernel-hien-tai>`
   - CentOS/RHEL: `dracut -f --kver <kernel-hien-tai>`

> **Lưu ý:** Script chỉ rebuild initramfs cho kernel **hiện tại**, không phải tất cả kernel, giúp rút ngắn thời gian từ vài phút xuống vài giây.

## Hướng dẫn sử dụng

### Cài đặt & chạy lần đầu

```bash
# Tải script
curl -O https://your-server.com/cve_2026_31431_smart_check.sh

# Cấp quyền thực thi
chmod +x cve_2026_31431_smart_check.sh

# Xem hướng dẫn
./cve_2026_31431_smart_check.sh
# hoặc
./cve_2026_31431_smart_check.sh --help
```

### Các flag và tình huống sử dụng

#### 1. `--check` — Kiểm tra không tương tác (dùng cho monitoring, cron, CI/CD)

```bash
./cve_2026_31431_smart_check.sh --check
```

- **Không** sửa đổi gì trên hệ thống
- Trả về exit code để script gọi có thể rẽ nhánh
- Phù hợp: chạy định kỳ qua cron, tích hợp vào pipeline

```bash
# Ví dụ: dùng trong cron, gửi cảnh báo nếu phát hiện lỗ hổng
0 6 * * * /opt/scripts/cve_2026_31431_smart_check.sh --check || \
  echo "CANH BAO CVE-2026-31431" | mail -s "Security Alert" admin@company.com
```

#### 2. `--scan` — Chạy tương tác (dùng khi sysadmin trực tiếp kiểm tra)

```bash
./cve_2026_31431_smart_check.sh --scan
```

- Hiển thị trạng thái chi tiết
- Nếu phát hiện CRITICAL: hỏi xác nhận trước khi sửa (y/n hoặc dialog whiptail nếu có)
- Phù hợp: sysadmin đang ngồi terminal, muốn kiểm tra thủ công từng máy

#### 3. `--fix` — Tự động vá (dùng khi triển khai hàng loạt)

```bash
./cve_2026_31431_smart_check.sh --fix
```

- Tự động áp dụng hardening nếu phát hiện lỗ hổng, **không hỏi**
- Nếu hệ thống đã an toàn hoặc đã được hardening, không làm gì thêm
- Phù hợp: triển khai qua Ansible, Salt, Puppet hoặc script deploy hàng loạt

```bash
# Ví dụ: triển khai hàng loạt qua SSH loop
for host in server-{01..50}.internal; do
  ssh root@"$host" 'bash -s' < cve_2026_31431_smart_check.sh --fix
done
```

### Bảng exit code

| Exit code | Ý nghĩa                                                       | Hành động khuyến nghị         |
| --------- | ------------------------------------------------------------- | ----------------------------- |
| **0**     | An toàn — kernel không bị ảnh hưởng, hoặc đã được hardening   | Không cần làm gì              |
| **1**     | Module không hoạt động, nhưng kernel nằm trong vùng ảnh hưởng | Cân nhắc hardening phòng ngừa |
| **2**     | **NGUY HIỂM** — module đang chạy trên kernel bị ảnh hưởng     | Cần hardening ngay            |
| **3**     | Lỗi — không đủ quyền root                                     | Chạy lại với sudo hoặc root   |

### Kiểm tra sau khi hardening

Sau khi chạy `--fix` hoặc `--scan`, cần **reboot** để đảm bảo module không còn trong memory:

```bash
# Kiểm tra lại sau reboot
./cve_2026_31431_smart_check.sh --check
echo $?   # Phải trả về 0
```

Xác nhận thủ công:

```bash
# Module không được liệt kê trong lsmod
lsmod | grep algif_aead    # Phải trả về rỗng

# File cấu hình đã tồn tại
cat /etc/modprobe.d/cve-2026-31431.conf

# Thử nạp module — phải thất bại
modprobe algif_aead 2>&1   # Phải báo lỗi
```

## Khả năng tương thích

| Distro        | Phiên bản đã test                 | initramfs tool     |
| ------------- | --------------------------------- | ------------------ |
| Ubuntu        | 16.04, 18.04, 20.04, 22.04, 24.04 | `update-initramfs` |
| Debian        | 9, 10, 11, 12                     | `update-initramfs` |
| CentOS / RHEL | 7, 8, 9                           | `dracut`           |
| Rocky Linux   | 8, 9                              | `dracut`           |
| AlmaLinux     | 8, 9                              | `dracut`           |

## Tự động hóa & tích hợp

### Chạy định kỳ qua cron

```bash
# Kiểm tra hàng ngày lúc 6:07 sáng, log ra syslog
7 6 * * * root /opt/scripts/cve_2026_31431_smart_check.sh --check || true
```

Kết quả được ghi vào syslog với tag `CVE-2026-31431`, có thể xem bằng:

```bash
journalctl -t CVE-2026-31431 --since "1 day ago"
# hoặc
grep CVE-2026-31431 /var/log/syslog
```

### Tích hợp Ansible

```yaml
- name: Kiem tra CVE-2026-31431
  script: cve_2026_31431_smart_check.sh --fix
  register: cve_result
  changed_when: "'CRITICAL' in cve_result.stdout"

- name: Reboot neu can
  reboot:
    msg: "Reboot sau khi hardening CVE-2026-31431"
  when: cve_result.changed
```

### Tích hợp monitoring (Nagios/Icinga/Sensu)

```bash
# Script đã tương thích sẵn với Nagios-style check nhờ exit code
# 0 = OK, 1 = WARNING, 2 = CRITICAL
./cve_2026_31431_smart_check.sh --check
```

## Gỡ bỏ hardening (nếu cần)

Trong trường hợp cần khôi phục module `algif_aead`:

```bash
rm /etc/modprobe.d/cve-2026-31431.conf
modprobe algif_aead
update-initramfs -u -k "$(uname -r)"   # Ubuntu/Debian
# hoặc
dracut -f --kver "$(uname -r)"         # CentOS/RHEL
```
