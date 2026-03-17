SECTIONS
{
    . = 0x00000000;
    .text : {
        FILL(0xCC);
        *(.text.strncmp)
        . = ALIGN(16);
        *(.text.strncpy)
        . = ALIGN(16);
        *(.text.strchr)
        . = ALIGN(16);
        *(.text.stricmp)
        . = ALIGN(16);
        *(.text.strtok)
        . = ALIGN(16);
        *(.text.initterm)
        . = ALIGN(16);
        *(.text.cxx_handler)
        . = ALIGN(16);
        *(.text.disable_thread_lib)
        *(.text*)
    }
    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.interp)
        *(.dynsym)
        *(.dynstr)
        *(.hash)
        *(.gnu.hash)
        *(.dynamic)
    }
}
