#include <assert.h>
#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <syscall.h>
#include <unistd.h>

unsigned long func_size;

/*
 * Fork a child process and set it up for tracing.
 * Replaces the child's image with the target program.
 */
pid_t run_target(char* const argv[])
{
    pid_t pid = fork();
    if (pid > 0) {
        return pid;
    } else if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace");
            exit(1);
        }
        execv(argv[0], argv);
        exit(1);
    } else {
        perror("fork");
        exit(1);
    }
}

void* get_elf_content(const char* sym_name, const char* file_name)
{
    // Open ELF file for reading
    int elf_fd = open(file_name, O_RDONLY);
    if (elf_fd < 0) {
        perror("failed to open file");
        return NULL;
    }

    // Get file size
    struct stat elf_stats;
    int ret = fstat(elf_fd, &elf_stats);
    if (ret < 0) {
        perror("fstat failed");
        close(elf_fd);
        return NULL;
    }
    long file_size = elf_stats.st_size;

    // Allocate memory for the file content
    void* file_content = malloc(file_size);
    if (!file_content) {
        perror("malloc failed");
        close(elf_fd);
        return NULL;
    }

    // Read ELF file content into memory
    ret = read(elf_fd, file_content, file_size);
    if (ret < file_size) {
        perror("read failed or incomplete");
        free(file_content);
        close(elf_fd);
        return NULL;
    }
    close(elf_fd);

    return file_content;
}

unsigned long parse_elf(const char* target_sym, void* file_contents)
{
    // TODO: Look up target_sym address in the elf binary and return its virtual
    Elf64_Ehdr *ehdr = file_contents;
    Elf64_Shdr *shdr = file_contents + ehdr->e_shoff;
    int symtab_idx = -1;
    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (shdr[i].sh_type == SHT_SYMTAB) {
            symtab_idx = i;
            break;
        }
    }
    if (symtab_idx == -1) return 0;
    Elf64_Sym *syms = file_contents + shdr[symtab_idx].sh_offset;
    int strtab_idx = shdr[symtab_idx].sh_link;
    char *strtab = file_contents + shdr[strtab_idx].sh_offset;
    int num_symbols = shdr[symtab_idx].sh_size / sizeof(Elf64_Sym);
    for (int i = 0; i < num_symbols; i++) {
        char *current_sym_name = strtab + syms[i].st_name;
        if (strcmp(current_sym_name, target_sym) == 0) {
            func_size = syms[i].st_size;
            return syms[i].st_value;
        }
    }
    // address. Return 0 if not found.
}

/*
 * Main debugger tracing loop.
 */
void run_tracer(pid_t child_pid, unsigned long addr, int nr_params)
{
    int wait_status;
    int run_idx = 1;
    int call_depth = 0;
    struct user_regs_struct regs;

    wait(&wait_status);

    // TODO: Implement tracing logic
    unsigned long data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)addr, NULL);
    unsigned char first_byte = data & 0xFF;
    if (first_byte == 0x55) {
        printf("PRF:: This function starts by pushing rbp\n");
    }

    unsigned long data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, child_pid, (void*)addr, (void*)data_trap);
    ptrace(PTRACE_CONT, child_pid, NULL, NULL);
    wait(&wait_status);

    unsigned long orig_return_addr = 0;
    unsigned long ret_data = 0;
    unsigned long ret_data_trap = 0;
    unsigned long orig_rsp = 0;
    while(WIFSTOPPED(wait_status)) {
        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
        regs.rip -= 1;
        ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
        if (regs.rip == addr) {
            unsigned long return_addr = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)regs.rsp, NULL);
            unsigned long long param_regs[6] = {regs.rdi, regs.rsi, regs.rdx, regs.rcx, regs.r8, regs.r9}; // first 6 params are passed in registers
        if (call_depth > 0) { // check if its a recursive call
            printf("PRF::     entered recursive call with (");
            if (nr_params > 0) {
             for (int i=0; i<nr_params-1; i++) {
                printf("%llu, ",param_regs[i]);
            }
            printf("%llu)\n",param_regs[nr_params-1]);
            } else {
                printf(")\n");
            }

        } else { // normal call 
            printf("PRF:: run #%d called with (", run_idx);
            if (nr_params > 0) {
                for (int i=0; i<nr_params-1; i++) {
                    printf("%llu, ",param_regs[i]);
                }
                printf("%llu):\n",param_regs[nr_params-1]);
            } else {
                printf("):\n");
            }
            run_idx++;
            orig_return_addr = return_addr;
            orig_rsp = regs.rsp;
            ret_data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)orig_return_addr, NULL);
            ret_data_trap = (ret_data & 0xFFFFFFFFFFFFFF00) | 0xCC;
            ptrace(PTRACE_POKETEXT, child_pid, (void*)orig_return_addr, (void*)ret_data_trap);
        }
        call_depth++;
        // Restore the original instruction and single step
        ptrace(PTRACE_POKETEXT, child_pid, (void*)addr, (void*)data);
        ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
        ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL);
        wait(&wait_status);
        ptrace(PTRACE_POKETEXT, child_pid, (void*)addr, (void*)data_trap);
        ptrace(PTRACE_CONT, child_pid, NULL, NULL);
        wait(&wait_status);

        } else if(orig_return_addr != 0 && regs.rip == orig_return_addr) {
            if (regs.rsp > orig_rsp) {
                printf("PRF::   call to function returned with %llu\n", regs.rax);
                ptrace(PTRACE_POKETEXT, child_pid, (void*)orig_return_addr, (void*)ret_data);
            ptrace(PTRACE_CONT, child_pid, NULL, NULL);
            wait(&wait_status);
            orig_return_addr = 0;
            ret_data = 0;
            orig_rsp = 0;
            call_depth = 0;
            } else {
                ptrace(PTRACE_POKETEXT, child_pid, (void*)orig_return_addr, (void*)ret_data);
                ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL);
                wait(&wait_status);
                ptrace(PTRACE_POKETEXT, child_pid, (void*)orig_return_addr, (void*)ret_data_trap);
                ptrace(PTRACE_CONT, child_pid, NULL, NULL);
                wait(&wait_status);
            }
        }
    }
}

int main(int argc, char* const argv[])
{
    if (argc < 4) {
        printf("usage: <sym_name> <number of input params> <elf_path> "
               "[optional input params for elf file]\n");
        return 0;
    }

    const char* sym_name  = argv[1];
    int nr_params         = strtol(argv[2], NULL, 10);
    const char* file_name = argv[3];

    // Put file content into memory for parsing
    void* file_content = get_elf_content(sym_name, file_name);

    // Find the symbol address
    unsigned long addr = parse_elf(sym_name, file_content);

    // Free the allocated memory
    free(file_content);

    // TODO: check if symbol was found
    if (addr == 0) {
        printf("PRF:: symbol not found\n");
        return 1;
    }
    printf("PRF:: symbol address is 0x%lX\n",addr);

    // Launch the target program
    pid_t child_pid = run_target(argv + 3);

    // Run the tracer
    run_tracer(child_pid, addr, nr_params);

    return 0;
}
