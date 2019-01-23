#include <stdint.h>
#include <stddef.h>

extern void *memfrob(void *s, size_t n);
extern uint64_t gather_bytes(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e);

int program(void *buff)
{
    unsigned char mem[] = {1,2,3,4,5,6,7,8};
    uint64_t ret;

    memfrob((void *)mem, sizeof(mem));
    memfrob((void *)mem, sizeof(mem));
    ret = * ((uint64_t *)mem);
    return ret;
}
