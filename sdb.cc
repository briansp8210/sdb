#include "sdb.h"

size_t DebugSession::AddBreakpoint(uint64_t addr) {
  if (addr >= text_addr_ && addr < text_addr_ + text_size_) {
    addr = (is_pie_ && is_running_) ? addr - text_load_base_ : addr;
    if (HasBreakpoint(addr)) {
      fprintf(stderr, "** Address already has a breakpoint.\n");
      return 0;
    } else {
      bps_[bp_count_++] = addr;
      bps_set_.insert(addr);
      if (is_running_) {
        DeployBreakpoint(addr);
      }
      return bp_count_ - 1;
    }
  } else {
    fprintf(stderr, "** Address is out-of-range.\n");
    return 0;
  }
}

void DebugSession::Continue() {
  RETURN_IF_NOT_RUNNING();

  long pc = GetRegister(GetRegOffset("rip"));
  long code = GetTextWord(pc);
  if ((code & 0xff) == 0xcc) {
    uint8_t byte;
    SCHECK_NE(pread(fd_, &byte, 1, pc - text_load_base_), -1);
    SetTextByte(pc, byte, code);

    SCHECK_NE(ptrace(PTRACE_SINGLESTEP, pid_, NULL, NULL), -1);
    WaitTracee();
    SetTextByte(pc, 0xcc, code);
  }

  SCHECK_NE(ptrace(PTRACE_CONT, pid_, NULL, NULL), -1);
  WaitTracee();
}

void DebugSession::DeleteBreakpoint(size_t bp_idx) {
  auto bp = bps_.find(bp_idx);
  if (bp == bps_.end()) {
    fprintf(stderr, "** No breakpoint number %lu.\n", bp_idx);
  } else {
    bps_.erase(bp);
    bps_set_.erase(bp->second);
    if (is_running_) {
      uint8_t byte;
      uint64_t offset = is_pie_ ? bp->second : bp->second - text_load_base_;
      SCHECK_NE(pread(fd_, &byte, 1, offset), -1);
      uint64_t addr = is_pie_ ? text_load_base_ + bp->second : bp->second;
      SetTextByte(addr, byte);
    }
  }
}

void DebugSession::Disassemble(const char *target) {
  RETURN_IF_NOT_LOADED();

  if (target == NULL && !next_disasm_addr_) {
    fputs("** no addr is given.\n", stderr);
  } else if (target != NULL) {
    uint64_t addr = strtoull(target, NULL, 0);
    if (addr >= text_addr_ && addr < text_addr_ + text_size_) {
      next_disasm_addr_ = PrintAssembly(addr, 10);
    } else {
      fprintf(stderr, "** Address is out-of-range.\n");
    }
  } else {
    if (next_disasm_addr_ >= text_addr_ && next_disasm_addr_ < text_addr_ + text_size_) {
      next_disasm_addr_ = PrintAssembly(next_disasm_addr_, 10);
    } else {
      fprintf(stderr, "** Address is out-of-range.\n");
    }
  }
}

void DebugSession::PrintHelpMessage() {
  printf("- break {instruction-address}: add a break point\n"
         "- cont: continue execution\n"
         "- delete {break-point-id}: remove a break point\n"
         "- disasm addr: disassemble instructions in a file or a memory region\n"
         "- dump addr [length]: dump memory content\n"
         "- exit: terminate the debugger\n"
         "- get reg: get a single value from a register\n"
         "- getregs: show registers\n"
         "- help: show this message\n"
         "- list: list break points\n"
         "- load {path/to/a/program}: load a program\n"
         "- run: run the program\n"
         "- vmmap: show memory layout\n"
         "- set reg val: set a single value to a register\n"
         "- si: step into instruction\n"
         "- start: start the program and stop at the first instruction\n");
}

void DebugSession::PrintRegister(const char *reg) {
  RETURN_IF_NOT_RUNNING();

  int reg_off = GetRegOffset(reg);
  if (reg_off >= 0) {
    long val = GetRegister(reg_off);
    printf("%s = %ld (%#lx)\n", reg, val, val);
  }
}

void DebugSession::PrintRegisters() {
  RETURN_IF_NOT_RUNNING();

  printf("RAX %-18lx", GetRegister(GetRegOffset("rax")));
  printf("RBX %-18lx", GetRegister(GetRegOffset("rbx")));
  printf("RCX %-18lx", GetRegister(GetRegOffset("rcx")));
  printf("RDX %-18lx\n", GetRegister(GetRegOffset("rdx")));
  printf("R8  %-18lx", GetRegister(GetRegOffset("r8")));
  printf("R9  %-18lx", GetRegister(GetRegOffset("r9")));
  printf("R10 %-18lx", GetRegister(GetRegOffset("r10")));
  printf("R11 %-18lx\n", GetRegister(GetRegOffset("r11")));
  printf("R12 %-18lx", GetRegister(GetRegOffset("r12")));
  printf("R13 %-18lx", GetRegister(GetRegOffset("r13")));
  printf("R14 %-18lx", GetRegister(GetRegOffset("r14")));
  printf("R15 %-18lx\n", GetRegister(GetRegOffset("r15")));
  printf("RDI %-18lx", GetRegister(GetRegOffset("rdi")));
  printf("RSI %-18lx", GetRegister(GetRegOffset("rsi")));
  printf("RBP %-18lx", GetRegister(GetRegOffset("rbp")));
  printf("RSP %-18lx\n", GetRegister(GetRegOffset("rsp")));
  printf("RIP %-18lx", GetRegister(GetRegOffset("rip")));
  printf("FLAGS %016lx\n", GetRegister(GetRegOffset("eflags")));
}

inline void DebugSession::ListBreakpoints() {
  for (auto &bp : bps_) {
    uint64_t addr = (is_pie_ && is_running_) ? text_load_base_ + bp.second : bp.second;
    printf("%3lu: %lx\n", bp.first, addr);
  }
}

void DebugSession::Load(const char *prog) {
  if (is_loaded_) {
    fprintf(stderr, "** Program has been loaded.\n");
    return;
  } else {
    is_loaded_ = true;
    prog_name_ = strdup(prog);
  }

  SCHECK_NE(fd_ = open(prog, O_RDONLY), -1);
  Elf *elf;
  ECHECK_NE(elf = elf_begin(fd_, ELF_C_READ, NULL), NULL);
  size_t shdrstrndx;
  ECHECK_NE(elf_getshdrstrndx(elf, &shdrstrndx), -1);

  Elf_Scn *scn = NULL;
  while ((scn = elf_nextscn(elf, scn)) != NULL) {
    Elf64_Shdr *shdr = elf64_getshdr(scn);
    char *section_name = elf_strptr(elf, shdrstrndx, shdr->sh_name);
    if (!strcmp(section_name, ".text")) {
      text_addr_ = (uint64_t)shdr->sh_addr;
      text_off_ = (uint64_t)shdr->sh_offset;
      text_size_ = (uint64_t)shdr->sh_size;
      break;
    }
  }

  char *ident;
  ECHECK_NE(ident = elf_getident(elf, NULL), NULL);
  uint16_t elf_type = *((uint16_t *)(&ident[16]));
  if (elf_type == ET_EXEC) {
    is_pie_ = false;
  } else if (elf_type == ET_DYN) {
    is_pie_ = true;
  }

  elf_end(elf);
  printf("** program '%s' loaded. entry point %#lx, vaddr %#lx, offset %#lx, size %#lx\n", prog, text_addr_, text_addr_, text_off_, text_size_);
}

void DebugSession::MemoryDump(const char *target) {
  RETURN_IF_NOT_RUNNING();

  if (target == NULL && !next_dump_addr_) {
    fputs("** no addr is given.\n", stderr);
  } else if (target != NULL) {
    uint64_t addr = strtoull(target, NULL, 0);
    MemoryDumpInternal(addr);
    next_dump_addr_ = addr + 0x50;
  } else {
    MemoryDumpInternal(next_dump_addr_);
    next_dump_addr_ += 0x50;
  }
}

void DebugSession::ExecuteTracee(bool stop_at_entry) {
  if (is_running_) {
    fprintf(stderr, "** program %s is already running.\n", prog_name_);
    dbg->Continue();
    return;
  }

  BuildArgv();
  is_running_ = true;
  pid_t pid;
  SCHECK_NE(pid = fork(), -1);
  if (pid == 0) {
    SCHECK_NE(ptrace(PTRACE_TRACEME, 0, NULL, NULL), -1);
    execvp(prog_name_, argv_.data());
  } else {
    pid_ = pid;
    printf("** pid %d\n", pid);

    int wstatus;
    SCHECK_NE(waitpid(pid, &wstatus, 0), -1);
    SCHECK_NE(ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_EXITKILL), -1);
    GetTextLoadBaseAddr();
    DeployAllBreakpoints();

    // If user has already set a breakpoint at entry point,
    // we need to do nothing here.
    if (stop_at_entry && !HasBreakpoint(text_addr_)) {
      size_t bp_idx = AddBreakpoint(text_addr_);
      SCHECK_NE(ptrace(PTRACE_CONT, pid, NULL, NULL), -1);

      int wstatus;
      SCHECK_NE(waitpid(pid_, &wstatus, 0), -1);
      DeleteBreakpoint(bp_idx);
      SetRegister("rip", GetRegister(GetRegOffset("rip")) - 1);
    } else {
      SCHECK_NE(ptrace(PTRACE_CONT, pid, NULL, NULL), -1);
      WaitTracee();
    }
  }
}

void DebugSession::SetRegister(const char *reg, int64_t val) {
  RETURN_IF_NOT_RUNNING();

  int reg_off = GetRegOffset(reg);
  if (reg_off >= 0) {
    SCHECK_NE(ptrace(PTRACE_POKEUSER, pid_, reg_off, val), -1);
  }
}

void DebugSession::SingleStep() {
  RETURN_IF_NOT_RUNNING();

  long pc = GetRegister(GetRegOffset("rip"));
  long code = GetTextWord(pc);
  if ((code & 0xff) == 0xcc) {
    uint8_t byte;
    SCHECK_NE(pread(fd_, &byte, 1, pc - text_load_base_), -1);
    SetTextByte(pc, byte, code);

    SCHECK_NE(ptrace(PTRACE_SINGLESTEP, pid_, NULL, NULL), -1);
    WaitTracee();
    SetTextByte(pc, 0xcc, code);
  } else {
    SCHECK_NE(ptrace(PTRACE_SINGLESTEP, pid_, NULL, NULL), -1);
    WaitTracee();
  }
}

void DebugSession::ShowMemoryMapping() {
  RETURN_IF_NOT_LOADED();

  if (!is_running_) {
    printf("%016lx-%016lx r-x %-8lx %s\n", text_addr_, text_addr_ + text_size_, text_off_, prog_name_);
  } else {
    char buf[MAX_BUF_LEN];
    FILE *fp;
    snprintf(buf, sizeof(buf), "/proc/%d/maps", pid_);
    SCHECK_NE(fp = fopen(buf, "r"), NULL);

    while (fgets(buf, sizeof(buf), fp) != NULL) {
      char info[MAX_BUF_LEN] = "", *tok;
      APPEND_FMT(info, "%016lx-", strtoul(strtok(buf, "-"), NULL, 16));
      APPEND_FMT(info, "%016lx ", strtoul(strtok(NULL, " \t"), NULL, 16));
      APPEND_FMT(info, "%.3s ", strtok(NULL, " \t"));
      APPEND_FMT(info, "%-8lx ", strtoul(strtok(NULL, " \t"), NULL, 16));
      strtok(NULL, " \t");
      strtok(NULL, " \t");
      APPEND_FMT(info, "%s\n", (tok = strtok(NULL, " \n\t")) ? tok : "");
      printf("%s", info);
    }
    fclose(fp);
  }
}

void DebugSession::BuildArgv() {
  argv_.push_back(prog_name_);
  char *token;
  do {
    token = strtok(NULL, " \n\t");
    argv_.push_back(token);
  } while (token != NULL);
}

inline void DebugSession::DeployBreakpoint(uint64_t addr) {
  addr = is_pie_ ? text_load_base_ + addr : addr;
  SetTextByte(addr, 0xcc);
}

inline void DebugSession::DeployAllBreakpoints() {
  for (auto &bp : bps_) {
    DeployBreakpoint(bp.second);
  }
}

inline long DebugSession::GetRegister(size_t reg_off) {
  long val;
  errno = 0;
  SCHECK_NE((val = ptrace(PTRACE_PEEKUSER, pid_, reg_off, NULL)) == -1 && errno != 0, true);
  return val;
}

inline long DebugSession::GetTextWord(uint64_t addr) {
  long code;
  errno = 0;
  SCHECK_NE((code = ptrace(PTRACE_PEEKTEXT, pid_, addr, NULL)) == -1 && errno != 0, true);
  return code;
}

inline bool DebugSession::HasBreakpoint(uint64_t addr) {
  addr = is_pie_ ? addr - text_load_base_ : addr;
  return bps_set_.count(addr);
}

void DebugSession::MemoryDumpInternal(uint64_t addr) {
  for (int i = 0; i < 5; ++i) {
    char ascii[17] = "";
    printf("%16lx: ", addr);

    for (int j = 0; j < 2; ++j) {
      long code = GetTextWord(addr + j * 8);
      for (int k = 0; k < 8; ++k) {
        uint8_t byte = (code >> (k * 8)) & 0xff;
        printf("%02x ", byte);
        ascii[j * 8 + k] = isprint(byte) ? byte : '.';
      }
    }
    printf(" |%s|\n", ascii);
    addr += 0x10;
  }
}

uint64_t DebugSession::PrintAssembly(uint64_t addr, size_t instr_nums) {
  uint64_t offset;
  if (!is_pie_) {
    offset = addr - (text_addr_ - text_off_);
  } else if (is_running_) {
    offset = addr - text_load_base_;
  } else {
    offset = addr;
  }
  size_t len = instr_nums * MAX_INS_LEN;
  len = std::min(len, text_off_ + text_size_ - offset);

  uint8_t *code;
  SCHECK_NE(code = (uint8_t *)malloc(len), NULL);
  SCHECK_NE(pread(fd_, code, len, offset), -1);

  size_t i;
  cs_insn *insn;
  size_t count = cs_disasm(cs_handle, code, len, addr, 0, &insn);
  if (count == 0) {
    fputs("** error: Failed to disassemble given code!", stderr);
  } else {
    for (i = 0; i < instr_nums && i < count; ++i) {
      char bytes[3 * 9 + 1] = "";
      for (int j = 0; j < insn[i].size && j < 8; ++j) {
        APPEND_FMT(bytes, "%02x ", insn[i].bytes[j]);
      }
      printf("%16lx: %-*s%-7s%s\n", insn[i].address, 3 * 9, bytes, insn[i].mnemonic, insn[i].op_str);
      if (insn[i].size > 8) {
        memset(bytes, 0, sizeof(bytes));
        for (int j = 8; j < insn[i].size; ++j) {
          APPEND_FMT(bytes, "%02x ", insn[i].bytes[j]);
        }
        printf("%16lx: %s\n", insn[i].address, bytes);
      }
    }
  }

  --i;
  return insn[i].address + insn[i].size;
}

void DebugSession::GetTextLoadBaseAddr() {
  char pathname[MAX_BUF_LEN];
  FILE *fp;

  snprintf(pathname, sizeof(pathname), "/proc/%d/stat", pid_);
  SCHECK_NE(fp = fopen(pathname, "r"), NULL);
  fscanf(fp, "%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%lu", &text_load_base_);
  fclose(fp);

  if (is_pie_) {
    text_addr_ += text_load_base_;
    next_disasm_addr_ += text_load_base_;
  }
}

void DebugSession::SetTextByte(uint64_t addr, uint8_t val, uint64_t orig_word) {
  if (orig_word == 0) {
    orig_word = GetTextWord(addr);
  }
  SCHECK_NE(ptrace(PTRACE_POKETEXT, pid_, addr, (orig_word & 0xffffffffffffff00) | val), -1);
}

void DebugSession::WaitTracee() {
  int wstatus;
  SCHECK_NE(waitpid(pid_, &wstatus, 0), -1);
  if (WIFEXITED(wstatus)) {
    is_running_ = false;
    if (is_pie_) {
      text_addr_ -= text_load_base_;
      next_disasm_addr_ -= text_load_base_;
    }

    int8_t code = WEXITSTATUS(wstatus);
    if (code == 0) {
      printf("** child process %d terminiated normally (code 0)\n", pid_);
    } else {
      printf("** child process %d terminiated with code %hhd\n", pid_, code);
    }
  } else {
    long pc = GetRegister(GetRegOffset("rip")) - 1;
    if (HasBreakpoint(pc)) {
      SetRegister("rip", pc);
      printf("** breakpoint @");
      PrintAssembly(pc, 1);
    }
  }
}

int GetRegOffset(const char *reg) {
  if (!strcmp(reg, "r15")) {
    return offsetof(struct user_regs_struct, r15);
  } else if (!strcmp(reg, "r14")) {
    return offsetof(struct user_regs_struct, r14);
  } else if (!strcmp(reg, "r13")) {
    return offsetof(struct user_regs_struct, r13);
  } else if (!strcmp(reg, "r12")) {
    return offsetof(struct user_regs_struct, r12);
  } else if (!strcmp(reg, "rbp")) {
    return offsetof(struct user_regs_struct, rbp);
  } else if (!strcmp(reg, "rbx")) {
    return offsetof(struct user_regs_struct, rbx);
  } else if (!strcmp(reg, "r11")) {
    return offsetof(struct user_regs_struct, r11);
  } else if (!strcmp(reg, "r10")) {
    return offsetof(struct user_regs_struct, r10);
  } else if (!strcmp(reg, "r9")) {
    return offsetof(struct user_regs_struct, r9);
  } else if (!strcmp(reg, "r8")) {
    return offsetof(struct user_regs_struct, r8);
  } else if (!strcmp(reg, "rax")) {
    return offsetof(struct user_regs_struct, rax);
  } else if (!strcmp(reg, "rcx")) {
    return offsetof(struct user_regs_struct, rcx);
  } else if (!strcmp(reg, "rdx")) {
    return offsetof(struct user_regs_struct, rdx);
  } else if (!strcmp(reg, "rsi")) {
    return offsetof(struct user_regs_struct, rsi);
  } else if (!strcmp(reg, "rdi")) {
    return offsetof(struct user_regs_struct, rdi);
  } else if (!strcmp(reg, "rip")) {
    return offsetof(struct user_regs_struct, rip);
  } else if (!strcmp(reg, "eflags")) {
    return offsetof(struct user_regs_struct, eflags);
  } else if (!strcmp(reg, "rsp")) {
    return offsetof(struct user_regs_struct, rsp);
  } else {
    return -1;
  }
}

int main(int argc, char **argv) {
  dbg = new DebugSession();
  elf_version(EV_CURRENT);
  if (cs_open(CS_ARCH_X86, CS_MODE_64, &cs_handle) != CS_ERR_OK) {
    exit(EXIT_FAILURE);
  }

  if (argc == 2) {
    dbg->Load(argv[1]);
  }

  char buf[MAX_BUF_LEN];
  while (printf("sdb> "), fgets(buf, sizeof(buf), stdin) != NULL) {
    char *cmd = strtok(buf, " \n\t");
    if (cmd == NULL) {
      continue;
    } else if (!strcmp(cmd, "load")) {
      dbg->Load(strtok(NULL, " \n\t"));
    } else if (!strcmp(cmd, "b") || !strcmp(cmd, "break")) {
      char *addr = strtok(NULL, " \n\t");
      if (addr != NULL) {
        dbg->AddBreakpoint(strtoul(addr, NULL, 0));
      }
    } else if (!strcmp(cmd, "c") || !strcmp(cmd, "cont")) {
      dbg->Continue();
    } else if (!strcmp(cmd, "delete")) {
      char *idx = strtok(NULL, " \n\t");
      if (idx != NULL) {
        dbg->DeleteBreakpoint(strtoul(idx, NULL, 0));
      }
    } else if (!strcmp(cmd, "d") || !strcmp(cmd, "disasm")) {
      dbg->Disassemble(strtok(NULL, " \n\t"));
    } else if (!strcmp(cmd, "x") || !strcmp(cmd, "dump")) {
      dbg->MemoryDump(strtok(NULL, " \n\t"));
    } else if (!strcmp(cmd, "q") || !strcmp(cmd, "exit")) {
      break;
    } else if (!strcmp(cmd, "g") || !strcmp(cmd, "get")) {
      char *reg = strtok(NULL, " \n\t");
      if (reg == NULL) {
        fprintf(stderr, "** error: missing operands\n");
        continue;
      }
      dbg->PrintRegister(reg);
    } else if (!strcmp(cmd, "getregs")) {
      dbg->PrintRegisters();
    } else if (!strcmp(cmd, "h") || !strcmp(cmd, "help")) {
      dbg->PrintHelpMessage();
    } else if (!strcmp(cmd, "l") || !strcmp(cmd, "list")) {
      dbg->ListBreakpoints();
    } else if (!strcmp(cmd, "r") || !strcmp(cmd, "run")) {
      dbg->ExecuteTracee(false);
    } else if (!strcmp(cmd, "s") || !strcmp(cmd, "set")) {
      char *reg = strtok(NULL, " \t");
      if (reg == NULL) {
        fprintf(stderr, "** error: missing operands\n");
        continue;
      }
      char *val = strtok(NULL, " \n\t");
      if (val == NULL) {
        fprintf(stderr, "** error: missing operands\n");
        continue;
      }
      dbg->SetRegister(reg, strtoll(val, NULL, 0));
    } else if (!strcmp(cmd, "si")) {
      dbg->SingleStep();
    } else if (!strcmp(cmd, "start")) {
      dbg->ExecuteTracee(true);
    } else if (!strcmp(cmd, "m") || !strcmp(cmd, "vmmap")) {
      dbg->ShowMemoryMapping();
    } else {
      fprintf(stderr, "** Undefined command: \"%s\".\n", cmd);
    }
  }

  return 0;
}
