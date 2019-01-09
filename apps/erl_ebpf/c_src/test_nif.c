#include "erl_nif.h"

#include <string.h>
#include <math.h>

#include <sys/ebpf.h>
#include <sys/ebpf_vm.h>

static void register_functions(struct ebpf_vm *vm);
ERL_NIF_TERM mk_atom(ErlNifEnv* env, const char* atom);
ERL_NIF_TERM mk_error(ErlNifEnv* env, const char* mesg);
ERL_NIF_TERM mk_ret_tuple(ErlNifEnv* env, const uint64_t retval);
void * memfrob(void *s, size_t n);


ERL_NIF_TERM
mk_atom(ErlNifEnv* env, const char* atom)
{
    ERL_NIF_TERM ret;

    if(!enif_make_existing_atom(env, atom, &ret, ERL_NIF_LATIN1))
    {
        return enif_make_atom(env, atom);
    }

    return ret;
}

ERL_NIF_TERM
mk_error(ErlNifEnv* env, const char* mesg)
{
    return enif_make_tuple2(env, mk_atom(env, "error"), mk_atom(env, mesg));
}

ERL_NIF_TERM
mk_ret_tuple(ErlNifEnv* env, const uint64_t retval)
{
    return enif_make_tuple2(env, mk_atom(env, "ok"), enif_make_int64(env, retval));
}

static ERL_NIF_TERM
ebpf_run(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifEnv* msg_env;
    ErlNifBinary ebpf_code;
    ErlNifBinary ebpf_memory;

    if(argc != 2)
    {
        return enif_make_badarg(env);
    }

    if(!enif_is_binary(env, argv[0]))
    {
        return mk_error(env, "arg0_not_a_binary");
    }
    if(!enif_inspect_binary(env, argv[0], &ebpf_code))
        return enif_make_badarg(env);

    if(!enif_is_binary(env, argv[1]))
    {
        return mk_error(env, "arg1_not_a_binary");
    }
    if(!enif_inspect_binary(env, argv[0], &ebpf_memory))
        return enif_make_badarg(env);

    msg_env = enif_alloc_env();
    if(msg_env == NULL)
    {
        return mk_error(env, "environ_alloc_error");
    }

    /* create ebpf VM */
    struct ebpf_vm *vm = ebpf_create();
    if(!vm) {
        return mk_error(env, "ebpf_create_vm_error");
    }

    register_functions(vm);

    int rv = ebpf_load(vm, ebpf_code.data, ebpf_code.size);
    if(rv < 0) {
        ebpf_destroy(vm);
        return mk_error(env, "ebpf_load_vm_error");
    }

    uint64_t ret;
    ret = ebpf_exec(vm, ebpf_memory.data, ebpf_memory.size);

    /* destroy ebpf */
    ebpf_destroy(vm);

    enif_free_env(msg_env);
    return mk_ret_tuple(env, ret);
}

static ErlNifFunc nif_funcs[] = {
    {"ebpf_run", 2, ebpf_run}
};

ERL_NIF_INIT(test_nif, nif_funcs, NULL, NULL, NULL, NULL);


/* MaxOSX and FreeBSD doesn't have memfrob */
#if defined(__APPLE__) || defined(__FreeBSD__)
void *
memfrob(void *s, size_t n)
{
        uint8_t *t = s;
        for (int i = 0; i < n; i++) {
                *(t + i) = *(t + i) ^ 42;
        }

        return s;
}
#endif

static uint64_t
gather_bytes(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e)
{
        return ((uint64_t)a << 32) | ((uint32_t)b << 24) | ((uint32_t)c << 16) |
               ((uint16_t)d << 8) | e;
}

static void
trash_registers(void)
{
#if 0
        /* Overwrite all caller-save registers */
        asm("mov $0xf0, %rax;"
            "mov $0xf1, %rcx;"
            "mov $0xf2, %rdx;"
            "mov $0xf3, %rsi;"
            "mov $0xf4, %rdi;"
            "mov $0xf5, %r8;"
            "mov $0xf6, %r9;"
            "mov $0xf7, %r10;"
            "mov $0xf8, %r11;");
#endif
}

static uint32_t
sqrti(uint32_t x)
{
        return sqrt(x);
}

/* Register ebpf VM functions */
static void
register_functions(struct ebpf_vm *vm)
{
        ebpf_register(vm, 0, "gather_bytes", gather_bytes);
        ebpf_register(vm, 1, "memfrob", memfrob);
        ebpf_register(vm, 2, "trash_registers", trash_registers);
        ebpf_register(vm, 3, "sqrti", sqrti);
        ebpf_register(vm, 4, "strcmp_ext", strcmp);
}
