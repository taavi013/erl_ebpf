unsigned char increment(unsigned char x);

int program(void *buff)
{
    unsigned char c = ((unsigned char *)buff)[0];
    unsigned char d;

    d = increment(c);
    return d;
}

unsigned char increment(unsigned char x)
{
    unsigned char n = 1;

    return x + n;
}
