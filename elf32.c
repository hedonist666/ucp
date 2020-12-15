#include <unicorn/unicorn.h>
#include <elf.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <capstone/capstone.h>
#include <stdint.h>
#include <gmodule.h>


#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"


#define DISASM

void hui() {
    printf("you are hacked by hedonist666");
}


char* get_file_contents(const char* fn) {
    static FILE* f;
    static int fd;
    f = fopen(fn, "r");
    fd = fileno(f); 
    struct stat st;
    fstat(fd, &st);
    return mmap(NULL, st.st_size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE, fd, 0);
}


const char* beautify(int flag, int type) {
    if (type == 0) {
        if (flag == PT_NULL) {return "PT_NULL";}
        else if (flag == PT_LOAD) {return "PT_LOAD";}
        else if (flag == PT_DYNAMIC) {return "PT_DYNAMIC";}
        else if (flag == PT_INTERP) {return "PT_INTERP";}
        else if (flag == PT_NOTE) {return "PT_NOTE";}
        else if (flag == PT_SHLIB) {return "PT_SHLIB";}
        else if (flag == PT_PHDR) {return "PT_PHDR";}
        else if (flag == PT_LOPROC) {return "PT_LOPROC";}
        else if (flag == PT_HIPROC) {return "PT_HIPROC";}
        else if (flag == PT_GNU_STACK) {return "PT_GNU_STACK";}
        else return "NOT VALID FLAG";
    }
}


typedef struct MapNode {
    char* start;
    char* end;
    char* data;
    bool mapped;
    struct MapNode* next;
} MapNode;

static MapNode* maps = NULL;
static MapNode* mapsEnd = NULL;

void push(uc_engine* uc, void* val, int size) {

}

void init_stack(uc_engine* uc) {
    char* start = (char*)-1;
    for (MapNode* e = maps; e != NULL; e = e->next) {
        if (e->start < start) start = e->start;
    }
    if ((uint32_t)start & 0xfff) {
        start -= (uint32_t)start & 0xffff;
    }
    uc_err err;
    err = uc_mem_map(uc, 0x0, start, UC_PROT_ALL);
    if (err != UC_ERR_OK) {
        printf("[!] init_stack error: %u (%s)\n", err, uc_strerror(err));
        exit(-1);
    }
    uint32_t rsp = (uint32_t)start/2;
    uc_reg_write(uc, UC_X86_REG_RSP, &rsp);
    printf("[*] Created stack from 0x%06x to %p with stack pointer = %p\n", 0, start, rsp);
}


//TODO
void map_and_write(uc_engine* uc, char* addr, char* data, int len, bool flush) {

    if (addr != NULL && data != NULL && len != 0) {
        if (mapsEnd == NULL) {
            maps = mapsEnd = malloc(sizeof(*maps));
            mapsEnd->start = addr;
            mapsEnd->end = addr + len;
            mapsEnd->mapped = false;
            mapsEnd->next = NULL;
            mapsEnd->data = data;
        }
        else {
            mapsEnd->next = malloc(sizeof(*maps));
            mapsEnd->next->start = addr;
            mapsEnd->next->end = addr + len;
            mapsEnd->next->mapped = false;
            mapsEnd = mapsEnd->next;
            mapsEnd->next = NULL;
            mapsEnd->data = data;
        }
    }

    int i = 0;
    puts("[*] Current maps:");
    if (maps == NULL) {
        perror("[!] INTERNAL ERROR (map list is null)\n");
        exit(-1);
    }
    for (MapNode* e = maps; e != NULL; e=e->next) {
        if (e->mapped) printf("%d: <%p, %p>\n", i, e->start, e->end);
        else printf("%d: <%p, %p> UNMAPPED\n", i, e->start, e->end);
    }
    if (flush) {
        uc_err err;
        puts("[*] MERGING MAPS TO ONE MEMORY BLOCK (maybe it is better to change algorithm)"); 
        char* start = (char*)(-1);
        char* end = (char*)(0);
        for (MapNode* e = maps; e != NULL; e=e->next) {
            if (e->start < start) start = e->start;
            if (e->end > end) end = e->end;
        }
        uint32_t _start = start;
        uint32_t len = end - start;
        if (len & 0xfff) {
            uint32_t old_len = len;
            len += 0x1000 - (len & 0xfff);
            printf("[*] Len (%d) is not divisible by 1024, changind to %d\n", old_len, len);
        }
        printf("[*] Creatin map from %p to %p\n", start, start + len);
        err = uc_mem_map(uc, start, len, UC_PROT_ALL);
        if (err != UC_ERR_OK) {
            printf("[!] Failed on uc_mem_map(uc, %p, %d, UC_PROT_ALL) with error returned: %u, (%s)\n", start, len, err, uc_strerror(err));
            exit(-1);
        }
        for (MapNode* e = maps; e != NULL; e=e->next) {
            if (!e->mapped) {
                err = uc_mem_write(uc, e->start, e->data, e->end-e->start);
                if (err != UC_ERR_OK) {
                    printf("[!] Failed on uc_mem_write() with error returned: %u(%s)\n", err, uc_strerror(err));
                    exit(-1);
                }
                e->mapped = true;
            }
        }
        puts("[*] Memory flushed (God bless)");
    }
}

typedef struct Regs {
    uint32_t eax, ebx, ecx, edx, esi, edi;
} Regs;


void regs_dump(Regs* regs) {
    printf(ANSI_COLOR_BLUE"eax:\t%p\nebx:\t%p\necx:\t%p\nedx:\t%p\nesi:\t%p\nedi:\t%p\n"ANSI_COLOR_RESET, 
            regs->eax, regs->ebx, regs->ecx, regs->edx, regs->esi, regs->edi);
}

void read_regs(uc_engine* uc, Regs* regs) {
    uc_reg_read(uc, UC_X86_REG_EAX, &regs->eax);
    uc_reg_read(uc, UC_X86_REG_EBX, &regs->ebx);
    uc_reg_read(uc, UC_X86_REG_ECX, &regs->ecx);
    uc_reg_read(uc, UC_X86_REG_EDX, &regs->edx);
    uc_reg_read(uc, UC_X86_REG_ESI, &regs->esi);
    uc_reg_read(uc, UC_X86_REG_EDI, &regs->edi);
}


int sig_handlers[1000];

void show_tree_node(gpointer key, gpointer value) {
    printf("%p: %p\n", key, value);
}

void show_tree(GTree* tr) {
    g_tree_foreach(tr, show_tree_node, NULL); 
}


void interrupt(uc_engine* uc, uint32_t num, GTree* skip_list) {
    static Regs regs;
    static uint32_t eip;
    printf("[*] Got interrupt: %d\n", num);
    read_regs(uc, &regs);
    regs_dump(&regs);
    switch (num) {
        case 0x80:
            if (regs.eax == 0x30) {
                sig_handlers[regs.ebx] = regs.ecx; 
            }
            break;
        /* DUE TO UNICORN ISSUE WE MUST CHANGE EIP FROM HOOK_CODE */
        case 0x3:
            if (sig_handlers[5]) {
                uc_reg_read(uc, UC_X86_REG_EIP, &eip);
                eip += 1;
                g_tree_insert(skip_list, eip, sig_handlers[5]);
            }
            break;
    }
}


#ifdef DISASM

csh handle;
cs_insn *instr;

void hook_code(uc_engine* uc, char* address, int size, GTree* skip_list) {
    int count;
    char data[size];
    uc_mem_read(uc, address, data, size);
    if (address == NULL) {
        puts("[*] Program finished, exiting");
        exit(0);
    }
    count = cs_disasm(handle, data, size, address, 0, &instr);
    if (count > 0) {
        printf(ANSI_COLOR_CYAN "0x%"PRIx32":" ANSI_COLOR_GREEN "\t%s" ANSI_COLOR_MAGENTA "\t\t%s" ANSI_COLOR_RESET "\n", instr->address, instr->mnemonic, instr->op_str);
    } 
    else {
        printf("ERROR: Failed to disassemble given code!\n");
        return;
    }
    if (!strcmp(instr->mnemonic, "syscall")) {
        puts("[!] OOOPS, syscall");
    }
    uint32_t jmp = g_tree_lookup(skip_list, address);
    if (jmp != 0) { 
        printf("[*] Value is in skip list, jumping to %p\n", jmp);
        uc_reg_write(uc, UC_X86_REG_EIP, &jmp);
    }
    cs_free(instr, count);
}


#else
void hook_code(uc_engine* uc, char* address, int size, void* user_data)  {

}
#endif



typedef struct Range {
    char* start;
    char* end;
} Range;


Range prepare(const char* fn, uc_engine* uc) {
    char* mem = get_file_contents(fn);
    Elf32_Ehdr* ehdr = mem;
    Elf32_Phdr* phdr = &mem[ehdr->e_phoff];
    printf("[*] Program Headers number: %d\n", ehdr->e_phnum);
    Range res = {0};
    for (int i = 0; i < ehdr->e_phnum; ++i) {
        printf("Header %d: %s\n", i, beautify(phdr[i].p_type, 0));
        if (phdr[i].p_type == PT_PHDR) {
            puts("Found PT_PHDR, mapping it to vitrual mem...");
            map_and_write(uc, phdr[i].p_vaddr, phdr, sizeof(phdr)*ehdr->e_phnum, false);
        }
        if (phdr[i].p_type == PT_LOAD) {
            puts("Found PT_LOAD, mapping it...");
            map_and_write(uc, phdr[i].p_vaddr, &mem[phdr[i].p_offset], phdr[i].p_memsz, false);
            if (phdr[i].p_flags == 5 || phdr[i].p_flags == 7) {
                puts("[*] Found (maybe) .text segment....");
                res.end = phdr[i].p_vaddr + phdr[i].p_memsz;
            }
        }
    }
    map_and_write(uc, NULL, NULL, 0, true);
    char* entry = ehdr->e_entry;
    printf("[*] Entry point is at %p\n", entry);
    res.start = entry;
    init_stack(uc);
    return res;
}


gint dumb_compare(char* a1, char* a2) {
    if (a1 > a2) return -1;
    if (a2 > a1) return 1;
    return 0;
}


int main(int argc, char** argv) {
    uc_engine* uc;
    uc_err err;
    uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    uc_hook trace, trap;
    Range rng = prepare(argv[1], uc);
    printf("[*] Starting from %p to %p\n", rng.start, rng.end);
#ifdef DISASM
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK) {
        puts("[!] Failed to init disasm (capstone)");
        return -1;
    }
#endif
    GTree* skip_list = g_tree_new(dumb_compare);
    uc_hook_add(uc, &trace, UC_HOOK_CODE, hook_code, skip_list, 1, 0);
    uc_hook_add(uc, &trap, UC_HOOK_INTR, interrupt, skip_list, 1, 0);
    uc_emu_start(uc, rng.start, rng.end, 0, 0);
    hui();
    return 0;
}
