# sdb

sdb is a gdb-like debugger implemented in C++. With the power of `ptrace` system call, it allows you to set breakpoints, single step execution (instruction level) and manipulate registers contents. Features that are practical during debugging like showing assembly and memory mapping are also available. You can find more information in Usage section.

This is the final project for NCTU APUE 2019.

## How to build

```bash
# Assuming you are using Ubuntu 18.04
sudo apt update && sudo apt install git g++ make libcapstone-dev libelf-dev -y
git clone https://github.com/briansp8210/sdb.git
cd sdb
make
```

## Usage

sdb supports following instructions:

```
- break {instruction-address}: add a break point
- cont: continue execution
- delete {break-point-id}: remove a break point
- disasm addr: disassemble instructions in a file or a memory region
- dump addr [length]: dump memory content
- exit: terminate the debugger
- get reg: get a single value from a register
- getregs: show registers
- help: show this message
- list: list break points
- load {path/to/a/program}: load a program
- run: run the program
- vmmap: show memory layout
- set reg val: set a single value to a register
- si: step into instruction
- start: start the program and stop at the first instruction
```