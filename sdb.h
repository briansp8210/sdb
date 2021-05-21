#ifndef SDB_H_
#define SDB_H_

#include <capstone/capstone.h>
#include <errno.h>
#include <fcntl.h>
#include <libelf.h>
#include <map>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <unordered_set>
#include <vector>

#define MAX_BUF_LEN (512 + 1)
#define MAX_INS_LEN 15

#define APPEND_FMT(dst, fmt, ...) sprintf(dst + strlen(dst), fmt, __VA_ARGS__)

// Check normal functions and system call.
#define SCHECK_NE(expr1, expr2) ERRMSG_EXIT(expr1, expr2, strerror(errno))
// Check functions in libelf.
#define ECHECK_NE(expr1, expr2) ERRMSG_EXIT(expr1, expr2, elf_errmsg(elf_errno()))
#define ERRMSG_EXIT(expr1, expr2, msg)                                                                                                                                                                                                         \
  do {                                                                                                                                                                                                                                         \
    if ((expr1) == (expr2)) {                                                                                                                                                                                                                  \
      fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, msg);                                                                                                                                                                                 \
      exit(EXIT_FAILURE);                                                                                                                                                                                                                      \
    }                                                                                                                                                                                                                                          \
  } while (0)

#define RETURN_IF_NOT_LOADED() RETURN_IF_COND(!is_loaded_, "** No program loaded")
#define RETURN_IF_NOT_RUNNING() RETURN_IF_COND(!is_running_, "** The program is not being run.")
#define RETURN_IF_COND(cond, msg)                                                                                                                                                                                                              \
  do {                                                                                                                                                                                                                                         \
    if ((cond)) {                                                                                                                                                                                                                              \
      fputs(msg "\n", stderr);                                                                                                                                                                                                                 \
      return;                                                                                                                                                                                                                                  \
    }                                                                                                                                                                                                                                          \
  } while (0)

class DebugSession {
public:
  size_t AddBreakpoint(uint64_t addr);
  void Continue();
  void DeleteBreakpoint(size_t bp_idx);
  void Disassemble(const char *addr);
  void ExecuteTracee(bool stop_at_entry);
  static void PrintHelpMessage();
  void PrintRegister(const char *reg);
  void PrintRegisters();
  inline void ListBreakpoints();
  void Load(const char *prog);
  void MemoryDump(const char *target);
  void SetRegister(const char *reg, int64_t val);
  void SingleStep();
  void ShowMemoryMapping();

private:
  int fd_;
  char *prog_name_;
  bool is_loaded_ = false;
  bool is_running_ = false;

  uint64_t text_addr_;
  uint64_t text_off_;
  uint64_t text_size_;
  uint64_t next_disasm_addr_;
  uint64_t next_dump_addr_;

  pid_t pid_;
  bool is_pie_;
  uint64_t text_load_base_;
  std::vector<char *> argv_;

  std::map<uint64_t, uint64_t> bps_;
  std::unordered_set<uint64_t> bps_set_;
  uint64_t bp_count_ = 0;

  void BuildArgv();
  inline void DeployBreakpoint(uint64_t addr);
  inline void DeployAllBreakpoints();
  void ExecuteTracee();
  inline long GetRegister(size_t reg_off);
  void GetTextLoadBaseAddr();
  inline long GetTextWord(uint64_t addr);
  inline bool HasBreakpoint(uint64_t addr);
  void MemoryDumpInternal(uint64_t addr);
  uint64_t PrintAssembly(uint64_t offset, size_t instr_count);
  inline void SetTextByte(uint64_t addr, uint8_t val, uint64_t orig_code = 0);
  void WaitTracee();
};

int GetRegOffset(const char *reg);

DebugSession *dbg;
csh cs_handle;

#endif // SDB_H_
