static unsigned char increment(unsigned char x);

extern int bpf_give_increment_value();

int program(void *buff)
{
    unsigned char c = ((unsigned char *)buff)[0];
    unsigned char d;

    d = increment(c);
    return d;
}

static unsigned char increment(unsigned char x)
{
    unsigned char n = bpf_give_increment_value();

    return x + n;
}
