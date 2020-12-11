#include <unicorn/unicorn.h>
#include <elf.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>


void hui() {
    printf("you are hacked by hedonist666");
}


char* get_file_contents(const char* fn) {
    FILE* f = fopen(fn, "r");
    int fd = fileno(f); 
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


void map_and_write(uc_engine* uc, char* addr, char* data, int len, bool flush) {
    typedef struct MapNode {
        long int start;
        long int end;
        struct MapNode* next;
    } MapNode;

    static MapNode* maps = NULL;
    static MapNode* mapsEnd = NULL;

    uc_err err;
    if (len & 0x3ff ) {
        long int old_len = len;
        len += 0x400 - (len & 0x3ff);
        printf("[*] Len (%d) is not divisible by 1024, changind to %d\n", old_len, len);
    }
    err = uc_mem_map(uc, addr, len, UC_PROT_ALL);
    if (err != UC_ERR_OK) {
        printf("[!] Failed on uc_mem_map(uc, %p, %d, UC_PROT_ALL) with error returned: %u\n", addr, len, err);
        exit(-1);
    }
    err = uc_mem_write(uc, addr, data, len);
    if (err != UC_ERR_OK) {
        printf("[!] Failed on uc_mem_write() with error returned: %u\n", err);
        exit(-1);
    }
    if (mapsEnd == NULL) {
        maps = mapsEnd = malloc(sizeof(*maps));
        mapsEnd->start = addr;
        mapsEnd->end = addr + len;
    }
    else {
        mapsEnd->next = malloc(sizeof(*maps));
        mapsEnd->next->start = addr;
        mapsEnd->next->end = addr + len;
        mapsEnd = mapsEnd->next;
    }
    int i = 0;
    puts("[*] Current maps:");
    for (MapNode* e = maps; e != NULL; e=e->next) {
        printf("%d: <%p, %p>\n", i, e->start, e->end);
    }
}

void prepare(const char* fn, uc_engine* uc) {
    char* mem = get_file_contents(fn);
    Elf64_Ehdr* ehdr = mem;
    Elf64_Phdr* phdr = &mem[ehdr->e_phoff];
    printf("[*] Program Headers number: %d\n", ehdr->e_phnum);
    for (int i = 0; i < ehdr->e_phnum; ++i) {
        printf("Header %d: %s\n", i, beautify(phdr[i].p_type, 0));
        /* TODO DUE TO MEMORY OVERLAP
        if (phdr[i].p_type == PT_PHDR) {
            puts("Found PT_PHDR, mapping it to vitrual mem...");
            map_and_write(uc, phdr[i].p_vaddr, phdr, sizeof(phdr)*ehdr->e_phnum);
        }
        */
        if (phdr[i].p_type == PT_LOAD) {
            puts("Found PT_LOAD, mapping it...");
            map_and_write(uc, phdr[i].p_vaddr, &mem[phdr[i].p_offset], phdr[i].p_memsz, false);
        }
    }
    char* entry = ehdr->e_entry;
    printf("[*] Entry point is at %p\n", entry);
}


int main(int argc, char** argv) {
    uc_engine* uc;
    uc_err err;
    uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    prepare(argv[1], uc);
    hui();
}
