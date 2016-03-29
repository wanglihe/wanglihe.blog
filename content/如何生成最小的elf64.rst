如何生成最小的elf64?
####################
:date: 2015-04-30 11:27
:author: wanglihe
:category: Uncategorized
:tags: elf, elf64, linux, smallest
:slug: 如何生成最小的elf64
:status: published

作为理解机器码如何执行的重要的一环，我需要制作一个最小最简单的程序。本来，这个东西应该是在硬件和软件的结合部分来学习的，也就是所谓的“固件
firmware”。但是我在理解了所有的东西之后，在讲解上，反倒是觉得先说说操作系统上的进程更好。因为代码运行这个东西本质上是一样的，不同的是用什么方法启动它。而且在操作系统上实现了之后，对于学习其他东西更为方便，毕竟启动只是一个命令的事，不用“加电重启”。那么接下来，我就说说我是如何制作我的最小的可执行程序的，同时讲解有关启动的必要的知识。

什么是elf64
^^^^^^^^^^^

计算机可以执行的指令其实是一些具体的命令有效编码成的二进制数后的一个二进制序列，不管它具体是什么吧，可以认为是一砣数据。那么计算机如何将其中的指令拿出来运行呢？所以需要一个具体的指示性的部分，告诉计算机，这段指令有多长，使用哪种cpu，从哪里开始，林林总总吧，这些东西。这些指示性的数据，一般存在文件头，加上其内部的真正的代码，就是一个有效的可执行程序了。windows系统上使用的这种头叫作PE，linux系统上，这种头就是elf，全称是Executable
and Linkable
Format，中文翻过来就比较土了，叫“可执行及可链接格式”。基本的elf是32位的数据格式，现在2015年了，大家的电脑基本都是64位的了，操作系统也是64位的了，那么自然，我们就要生成对应的64位的elf64才能在现有的系统上正常运行。

从最简单的c程序开始
^^^^^^^^^^^^^^^^^^^

直接写实在是太难，于是我选择了从现有的程序进行简化。顺便还能说说程序的结构，一举两得。那么就从最简单的c程序开始吧，或者说最简单的linux的c程序开始。最简单的c程序是什么样呢？你一定想到了Hello
World吧？不不不，那个很复杂，又是创建字符串，又是输出到屏幕的，太大了。最简单的c程序是一段空代码，但是按照linux的要求，一定要返回一个退出值的程序。代码如下：

.. code-block:: c

    int main() {
        return 66;
    }

嗯，连头文件都没有，使用gcc编译运行后直接返回66，当然66是看不到的，因为没有写屏嘛，需要用echo
$?，意思是查后最后一个进程的退出值。但是这个程序编译后并不简单哦。用file查看一下：

.. code-block:: shell

     return66: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=01e7748a334c759245f69141c7291bd7d4207a5d, not stripped

首先我们看到文件是elf64的，但是是动态链接，那么接下来将程序化简吧：

.. code-block:: shell

    gcc -static -o return66 return66.c
    file return66
    return66: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.32, BuildID[sha1]=c5469005e4355c287ab21bf8ce73c1225dfa400c, not stripped

这个文件已经是一个可以独立运行的简单可执行文件了，但是如果看下大小的话，有729k，都是些什么东西这么大呢？用objdump
-d看一下，超级多的汇编代码被反编译出来了。太长，就不贴了。总之，gcc将好多无关的代码混进来了。这些代码其实是gcc为了软件的功能，加入到可执行文件中的，比如初始化内存池什么的，但是这些代码并不符合我们的需求，我们要最简。所以，将这些代码都干掉！

.. code-block:: shell

    gcc -static -nostartfiles -o return66 return66.c
    /usr/bin/ld: warning: cannot find entry symbol _start; defaulting to 000000000040010c

都干掉了，咦，找不到\_start是什么鬼？问题是这样的，程序的开始需要一个叫作入口的东西，其实就是一个确定的内存地址，比如那个40010c，入口的指令是第一条被执行的指令。一般呢，gcc会自动生成一个叫作\_start的入口，用“符号”标识，等到用的时候根据这个找到相关地址，就在那些startfiles里。但是现在我们不用了，于是就悲剧了。现在程序编译好却无法运行了。不怕，我们可以指定入口嘛。看看我们的源码，我们有main呢嘛。

.. code-block:: shell

    gcc -static -nostartfiles -o return66 -Wl,-e,main return66.c
    file return66
    return66: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, BuildID[sha1]=2dad238b785b9d9c643029c4852d84d0405d868e, not stripped
    ./return66
    Segmentation fault

再编，好，编译成功，而且此时的程序已经只有1.3k大小了，接近了我们的目标。再运行。程序崩溃了。因为什么呢？这里需要些函数调用相关的知识，简单的说就是函数调用前需要初始化内存栈，调用后也需要反向操作，退回一层内存栈。main原则上是c语言程序的第一个被调用的函数，所以调用前需要初始化才能正确给出返回值。但是我们将\_start干掉了，所以函数调用失败了。我们能用c写出一个\_start初始化的部分么？不幸，原则上，函数是c语言生成代码的底层极限，再下面是汇编语言的应用范围了。而且写一大堆汇编也不是本文的目的。那怎么办呢？其实，main函数是执行了的，错出在返回的部分。而正常的程序退出，也是在得到main的返回值再调linux的退出指令结束进程。我们直接调用系统退出命令不就成了？这里我们查一下man
syscalls和man
syscall，就可以得到直接进入系统调用的方法。于是代码是这样：

.. code-block:: c

    #include <syscall.h>
    int main() {
        syscall(SYS_exit, 66);
    }

使用上面同样的命令编译运行，得到预期结果啦！这个就是c能编出的最小的elf64的可执行文件了，大小是1784个byte，但还不是极限，我们来看看里面都有什么。

.. code-block:: shell

    readelf -Ss return66
    There are 9 section headers, starting at offset 0x4b8:

    Section Headers:
      [Nr] Name              Type             Address           Offset
           Size              EntSize          Flags  Link  Info  Align
      [ 0]                   NULL             0000000000000000  00000000
           0000000000000000  0000000000000000           0     0     0
      [ 1] .note.gnu.build-i NOTE             0000000000400120  00000120
           0000000000000024  0000000000000000   A       0     0     4
      [ 2] .text             PROGBITS         0000000000400150  00000150
           0000000000000060  0000000000000000  AX       0     0     16
      [ 3] .eh_frame         PROGBITS         00000000004001b0  000001b0
           0000000000000068  0000000000000000   A       0     0     8
      [ 4] .tbss             NOBITS           0000000000601000  00000218
           0000000000000004  0000000000000000 WAT       0     0     4
      [ 5] .comment          PROGBITS         0000000000000000  00000218
           0000000000000039  0000000000000001  MS       0     0     1
      [ 6] .shstrtab         STRTAB           0000000000000000  00000251
           000000000000004d  0000000000000000           0     0     1
      [ 7] .symtab           SYMTAB           0000000000000000  000002a0
           0000000000000198  0000000000000018           8     7     8
      [ 8] .strtab           STRTAB           0000000000000000  00000438
           000000000000007c  0000000000000000           0     0     1
    Key to Flags:
      W (write), A (alloc), X (execute), M (merge), S (strings), l (large)
      I (info), L (link order), G (group), T (TLS), E (exclude), x (unknown)
      O (extra OS processing required) o (OS specific), p (processor specific)

    Symbol table '.symtab' contains 17 entries:
       Num:    Value          Size Type    Bind   Vis      Ndx Name
         0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND 
         1: 0000000000400120     0 SECTION LOCAL  DEFAULT    1 
         2: 0000000000400150     0 SECTION LOCAL  DEFAULT    2 
         3: 00000000004001b0     0 SECTION LOCAL  DEFAULT    3 
         4: 0000000000601000     0 SECTION LOCAL  DEFAULT    4 
         5: 0000000000000000     0 SECTION LOCAL  DEFAULT    5 
         6: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS return66.c
         7: 0000000000400170    38 FUNC    GLOBAL DEFAULT    2 syscall
         8: 0000000000000000     4 TLS     GLOBAL DEFAULT    4 errno
         9: 00000000004001a3     0 NOTYPE  GLOBAL DEFAULT    2 __syscall_error_1
        10: 0000000000000000     4 TLS     GLOBAL DEFAULT    4 __libc_errno
        11: 00000000004001a0    16 FUNC    GLOBAL DEFAULT    2 __syscall_error
        12: 0000000000601000     0 NOTYPE  GLOBAL DEFAULT    3 __bss_start
        13: 0000000000400150    26 FUNC    GLOBAL DEFAULT    2 main
        14: 0000000000601000     0 NOTYPE  GLOBAL DEFAULT    3 _edata
        15: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND _GLOBAL_OFFSET_TABLE_
        16: 0000000000601000     0 NOTYPE  GLOBAL DEFAULT    3 _end

嗯，有编译好的代码，也有各种看不懂的头和相关符号表。好吧，使用编译器的极限我们达到了，接下来就是把main里面的函数体用汇编来一遍，将什么syscall\_error之类的自动生成的部分干掉。好，那我们看看代码里究竟有什么呢？


.. code-block:: shell

    objdump -d return66

    return66: file format elf64-x86-64


    Disassembly of section .text:

    0000000000400150 <main>:
     400150: 55 push %rbp
     400151: 48 89 e5 mov %rsp,%rbp
     400154: be 42 00 00 00 mov $0x42,%esi
     400159: bf 3c 00 00 00 mov $0x3c,%edi
     40015e: b8 00 00 00 00 mov $0x0,%eax
     400163: e8 08 00 00 00 callq 400170 <syscall>
     400168: b8 00 00 00 00 mov $0x0,%eax
     40016d: 5d pop %rbp
     40016e: c3 retq 
     40016f: 90 nop

    0000000000400170 <syscall>:
     400170: 48 89 f8 mov %rdi,%rax
     400173: 48 89 f7 mov %rsi,%rdi
     400176: 48 89 d6 mov %rdx,%rsi
     400179: 48 89 ca mov %rcx,%rdx
     40017c: 4d 89 c2 mov %r8,%r10
     40017f: 4d 89 c8 mov %r9,%r8
     400182: 4c 8b 4c 24 08 mov 0x8(%rsp),%r9
     400187: 0f 05 syscall 
     400189: 48 3d 01 f0 ff ff cmp $0xfffffffffffff001,%rax
     40018f: 0f 83 0b 00 00 00 jae 4001a0 <__syscall_error>
     400195: c3 retq 
     400196: 66 2e 0f 1f 84 00 00 nopw %cs:0x0(%rax,%rax,1)
     40019d: 00 00 00 

    00000000004001a0 <__syscall_error>:
     4001a0: 48 f7 d8 neg %rax

    00000000004001a3 <__syscall_error_1>:
     4001a3: 64 89 04 25 fc ff ff mov %eax,%fs:0xfffffffffffffffc
     4001aa: ff 
     4001ab: 48 83 c8 ff or $0xffffffffffffffff,%rax
     4001af: c3 retq

这里可以看到，系统编译了main函数，并且自动生成了syscall相关的几个函数，最终syscall这个函数执行了0f05（050f，大小尾的问题）这个指令叫syscall，是一个cpu指令。我们不需要什么错误之类的函数，为了尽量小，也不需要syscall这个函数，所以只要知道syscall这个指令怎么用了，查一下相关的x86\_64\ `手册 <http://www.x86-64.org/documentation/abi.pdf>`__\ ，看了一下，rax里是系统调用编号，rdi,rsi相关寄存器存调用参数。好了，那就开始用nasm重新来一下吧。首先得知道调用编号。

.. code-block:: c

    gcc -E return66.c
    # 1 "return66.c"
    # 1 "<built-in>"
    # 1 "<command-line>"
    # 1 "/usr/include/stdc-predef.h" 1 3 4
    # 1 "<command-line>" 2
    # 1 "return66.c"
    # 1 "/usr/include/syscall.h" 1 3 4
    # 1 "/usr/include/x86_64-linux-gnu/sys/syscall.h" 1 3 4
    # 24 "/usr/include/x86_64-linux-gnu/sys/syscall.h" 3 4
    # 1 "/usr/include/x86_64-linux-gnu/asm/unistd.h" 1 3 4
    # 12 "/usr/include/x86_64-linux-gnu/asm/unistd.h" 3 4
    # 1 "/usr/include/x86_64-linux-gnu/asm/unistd_64.h" 1 3 4
    # 13 "/usr/include/x86_64-linux-gnu/asm/unistd.h" 2 3 4
    # 25 "/usr/include/x86_64-linux-gnu/sys/syscall.h" 2 3 4






    # 1 "/usr/include/x86_64-linux-gnu/bits/syscall.h" 1 3 4
    # 32 "/usr/include/x86_64-linux-gnu/sys/syscall.h" 2 3 4
    # 1 "/usr/include/syscall.h" 2 3 4
    # 2 "return66.c" 2
    int main() {
        syscall(60, 66);
        return 0;
    }

系统调用编号是60。于是生成如下汇编：

.. code-block:: asm

    [bits 64]

    section .text
    global _start
    _start:                ; ELF entry point
    mov rax, 60            ; sys_exit
    mov rdi, 0x42          ; 66 本大王王礼鹤的生日暗合宇宙最终答案！
    syscall

编译：

.. code-block:: shell

    nasm -f elf64 -o exit66.o exit66.asm
    ld -o exit66 exit66.o

程序正常运行，返回了66的结果，而且大小缩减到了712个byte。再来看看这个小文件里都有什么。objdum
-D的输出长得和汇编一样，就不贴了，但是readelf则还有很多输出内容：

.. code-block:: shell

    readelf -a exit66
    ELF Header:
      Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
      Class:                             ELF64
      Data:                              2's complement, little endian
      Version:                           1 (current)
      OS/ABI:                            UNIX - System V
      ABI Version:                       0
      Type:                              EXEC (Executable file)
      Machine:                           Advanced Micro Devices X86-64
      Version:                           0x1
      Entry point address:               0x400080
      Start of program headers:          64 (bytes into file)
      Start of section headers:          392 (bytes into file)
      Flags:                             0x0
      Size of this header:               64 (bytes)
      Size of program headers:           56 (bytes)
      Number of program headers:         1
      Size of section headers:           64 (bytes)
      Number of section headers:         5
      Section header string table index: 2

    Section Headers:
      [Nr] Name              Type             Address           Offset
           Size              EntSize          Flags  Link  Info  Align
      [ 0]                   NULL             0000000000000000  00000000
           0000000000000000  0000000000000000           0     0     0
      [ 1] .text             PROGBITS         0000000000400080  00000080
           000000000000000c  0000000000000000  AX       0     0     16
      [ 2] .shstrtab         STRTAB           0000000000000000  0000008c
           0000000000000021  0000000000000000           0     0     1
      [ 3] .symtab           SYMTAB           0000000000000000  000000b0
           00000000000000a8  0000000000000018           4     3     8
      [ 4] .strtab           STRTAB           0000000000000000  00000158
           000000000000002b  0000000000000000           0     0     1
    Key to Flags:
      W (write), A (alloc), X (execute), M (merge), S (strings), l (large)
      I (info), L (link order), G (group), T (TLS), E (exclude), x (unknown)
      O (extra OS processing required) o (OS specific), p (processor specific)

    There are no section groups in this file.

    Program Headers:
      Type           Offset             VirtAddr           PhysAddr
                     FileSiz            MemSiz              Flags  Align
      LOAD           0x0000000000000000 0x0000000000400000 0x0000000000400000
                     0x000000000000008c 0x000000000000008c  R E    200000

     Section to Segment mapping:
      Segment Sections...
       00     .text 

    There is no dynamic section in this file.

    There are no relocations in this file.

    The decoding of unwind sections for machine type Advanced Micro Devices X86-64 is not currently supported.

    Symbol table '.symtab' contains 7 entries:
       Num:    Value          Size Type    Bind   Vis      Ndx Name
         0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND 
         1: 0000000000400080     0 SECTION LOCAL  DEFAULT    1 
         2: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS exit66.asm
         3: 0000000000400080     0 NOTYPE  GLOBAL DEFAULT    1 _start
         4: 000000000060008c     0 NOTYPE  GLOBAL DEFAULT    1 __bss_start
         5: 000000000060008c     0 NOTYPE  GLOBAL DEFAULT    1 _edata
         6: 0000000000600090     0 NOTYPE  GLOBAL DEFAULT    1 _end

    No version information found in this file.

这里可以看到这个elf里还是有很多段的（session），基本上，我们只需要.text段，而其他的几个段是ld自动生成的，这个代码应该可以认为是ld生成程序的最小极限了，我没有找到用ld进一步缩减大小的方法，但是查elf的相关标准，除了programmer
header是必选外，session
header是可选的，也就是说，除了.text，其他的是可以删除进一步减小大小。这时我找到了一篇变态的\ `博客 <http://www.muppetlabs.com/~breadbox/software/tiny/teensy.html>`__\ ，里面直接用bin的方法生成elf，也就是说将头的数据写进汇编代码。于是，照葫芦画瓢，我也来做了一个64位版的，但是我没那么变态将可执行部分进一步压缩，我是目的还是要生成一个结构完整的代码。代码如下：

.. code-block:: asm

    [bits 64]

        org     0x400000 ;program offset参见上文readelf输出中LOAD

    ;struct from elf.h
    ;typedef struct
    ;{
    ;  unsigned char    e_ident[EI_NIDENT];    /* Magic number and other info */
    ;  Elf64_Half    e_type;            /* Object file type */
    ;  Elf64_Half    e_machine;         /* Architecture */
    ;  Elf64_Word    e_version;         /* Object file version */
    ;  Elf64_Addr    e_entry;           /* Entry point virtual address */
    ;  Elf64_Off     e_phoff;           /* Program header table file offset */
    ;  Elf64_Off     e_shoff;           /* Section header table file offset */
    ;  Elf64_Word    e_flags;           /* Processor-specific flags */
    ;  Elf64_Half    e_ehsize;          /* ELF header size in bytes */
    ;  Elf64_Half    e_phentsize;       /* Program header table entry size */
    ;  Elf64_Half    e_phnum;           /* Program header table entry count */
    ;  Elf64_Half    e_shentsize;       /* Section header table entry size */
    ;  Elf64_Half    e_shnum;           /* Section header table entry count */
    ;  Elf64_Half    e_shstrndx;        /* Section header string table index */
    ;} Elf64_Ehdr;
      
    ehdr:                                                 ;   Elf64_Ehdr
                  db      0x7F, "ELF", 2, 1, 1, 0         ;   e_ident
          times 8 db      0
                  dw      2                               ;   e_type
                  dw      62                              ;   e_machine
                  dd      1                               ;   e_version
                  dq      _start                          ;   e_entry
                  dq      phdr - $$                       ;   e_phoff
                  dq      0                               ;   e_shoff
                  dd      0                               ;   e_flags
                  dw      ehdrsize                        ;   e_ehsize
                  dw      phdrsize                        ;   e_phentsize
                  dw      1                               ;   e_phnum
                  dw      0                               ;   e_shentsize
                  dw      0                               ;   e_shnum
                  dw      0                               ;   e_shstrndx

    ehdrsize      equ     $ - ehdr
    ;struct from elf.h
    ;typedef struct
    ;{
    ;  Elf64_Word    p_type;         /* Segment type */
    ;  Elf64_Word    p_flags;        /* Segment flags */
    ;  Elf64_Off     p_offset;       /* Segment file offset */
    ;  Elf64_Addr    p_vaddr;        /* Segment virtual address */
    ;  Elf64_Addr    p_paddr;        /* Segment physical address */
    ;  Elf64_Xword   p_filesz;       /* Segment size in file */
    ;  Elf64_Xword   p_memsz;        /* Segment size in memory */
    ;  Elf64_Xword   p_align;        /* Segment alignment */
    ;} Elf64_Phdr;

    phdr:                                                 ;   Elf64_Phdr
                  dd      1                               ;   p_type
                  dd      5                               ;   p_flags
                  dq      0                               ;   p_offset
                  dq      $$                              ;   p_vaddr
                  dq      $$                              ;   p_paddr
                  dq      filesize                        ;   p_filesz
                  dq      filesize                        ;   p_memsz
                  dq      0x1000                          ;   p_align

    phdrsize      equ     $ - phdr

    _start:
        mov rax, 60            ; sys_exit
        mov rdi, 0x42          ; 66
        syscall

    filesize      equ     $ - $$

ok，试一下结果吧

.. code-block:: shell

    nasm -f bin -o asmexit66bin exit66bin.asm
    chmod u+x asmexit66bin

运行结果完全正确。再看看内容吧。这个时候由于没有段，objdump已经读不出内容了，但是readelf还可以:

.. code-block:: shell

    readelf -a asmexit66bin
    ELF Header:
      Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
      Class:                             ELF64
      Data:                              2's complement, little endian
      Version:                           1 (current)
      OS/ABI:                            UNIX - System V
      ABI Version:                       0
      Type:                              EXEC (Executable file)
      Machine:                           Advanced Micro Devices X86-64
      Version:                           0x1
      Entry point address:               0x4000078
      Start of program headers:          64 (bytes into file)
      Start of section headers:          0 (bytes into file)
      Flags:                             0x0
      Size of this header:               64 (bytes)
      Size of program headers:           56 (bytes)
      Number of program headers:         1
      Size of section headers:           0 (bytes)
      Number of section headers:         0
      Section header string table index: 0

    There are no sections in this file.

    There are no sections to group in this file.

    Program Headers:
      Type           Offset             VirtAddr           PhysAddr
                     FileSiz            MemSiz              Flags  Align
      LOAD           0x0000000000000000 0x0000000004000000 0x0000000004000000
                     0x0000000000000084 0x0000000000000084  R E    1000

    There is no dynamic section in this file.

    There are no relocations in this file.

    The decoding of unwind sections for machine type Advanced Micro Devices X86-64 is not currently supported.

    Dynamic symbol information is not available for displaying symbols.

    No version information found in this file.

这就是一个结构完整的最小的elf64文件了，大小只有132个byte哟。喜欢的人可以拿它当教具，讲解函数入口，基本汇编了。
