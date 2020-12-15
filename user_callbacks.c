//0x8048103:

void f1(uc_engine* uc, void* data) {
    uint32_t esp;
    uc_reg_read(uc, UC_X86_REG_ESP, &esp);
    hexdump(uc, esp, 16*3);
}

void f2(uc_engine* uc, void* data) {
    puts("dumping password...");
    hexdump(uc, 0x80482d1, 16*3);
    puts("dumping data...");
    hexdump(uc, 0x8048251, 16);
    puts("suka??");
}

void init_skip_list(GTree* lst) {
    add_cb(lst, 0x8048103, f1, false); 
    add_cb(lst, 0x804814e, f2, false);
}
