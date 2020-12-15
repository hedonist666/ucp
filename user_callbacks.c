//EXAMPLE

void f1(uc_engine* uc, void* data) {
    uint32_t esp;
    uc_reg_read(uc, UC_X86_REG_ESP, &esp);
    hexdump(uc, esp, 16*3);
}

init_skip_list(GTree* lst) {
    add_cb(lst, 0x8048103, f1, false); 
}
