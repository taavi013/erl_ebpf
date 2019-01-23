#include "erl_nif.h"

#include <string.h>
#include <math.h>
#include <assert.h>

#include <sys/ebpf.h>
#include <sys/ebpf_vm.h>

static void ebpf_vm_dtor(ErlNifEnv* env, void* obj);
static void register_functions(struct ebpf_vm *vm);
ERL_NIF_TERM mk_atom(ErlNifEnv* env, const char* atom);
ERL_NIF_TERM mk_error(ErlNifEnv* env, const char* mesg);
ERL_NIF_TERM mk_ret_tuple(ErlNifEnv* env, const uint64_t retval);
void * memfrob(void *s, size_t n);

extern int load_elf(struct ebpf_vm *vm, const void *elf, size_t elf_size, char **errmsg);

static ERL_NIF_TERM atom_ok;
static ERL_NIF_TERM atom_error;

static ErlNifResourceType* EBPF_VM_RESOURCE = NULL;

/* NIF load function
 *
 * we create resource type ebpf_vm_type
 * and assing destructor function
 */
static int load(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM load_info)
{
  atom_ok = enif_make_atom(env, "ok");
  atom_error = enif_make_atom(env, "error");
    
  ErlNifResourceType* rt = enif_open_resource_type(env, NULL,
						   "ebpf_vm_type",
						   ebpf_vm_dtor,
						   ERL_NIF_RT_CREATE, NULL);
  if(rt == NULL)
    return -1;

  assert(EBPF_VM_RESOURCE == NULL);
  EBPF_VM_RESOURCE = rt;
  return 0;
}

/* Destructor function for resource ebpf_vm_type */
static void ebpf_vm_dtor(ErlNifEnv* env, void* obj)
{
  struct ebpf_vm** vm = obj;

  if(*vm)
    ebpf_destroy(*vm);
}

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
    return enif_make_tuple2(env, atom_error, mk_atom(env, mesg));
}

ERL_NIF_TERM
mk_ret_tuple(ErlNifEnv* env, const uint64_t retval)
{
    return enif_make_tuple2(env, atom_ok, enif_make_int64(env, retval));
}

/*
 * Create ebpf_vm and load code
 */
static ERL_NIF_TERM
create(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
  ErlNifBinary ebpf_code;
  ERL_NIF_TERM res = {0};
  int arity;
  const ERL_NIF_TERM *arg_tuple;
  char binary_type[32];
  ErlNifBinary elf_binary;
  
  if(argc != 1)
    return enif_make_badarg(env);
  
  /* create ebpf VM */
  struct ebpf_vm **vm = enif_alloc_resource(EBPF_VM_RESOURCE, sizeof(struct ebpf_vm*));
  *vm = ebpf_create();
  if(!*vm){
    enif_release_resource(vm);
    return mk_error(env, "ebpf_create_vm_error");
  }

  register_functions(*vm);

 
  if(enif_is_binary(env, argv[0])) {
    /* argv[0] is simple binary i.e. contains runnable eBPF code */
    if(!enif_inspect_binary(env, argv[0], &ebpf_code))
      return enif_make_badarg(env);

    int rv  = ebpf_load(*vm, ebpf_code.data, ebpf_code.size);
    if(rv < 0){
      ebpf_destroy(*vm);
      return mk_error(env, "ebpf_load_code_error");
    }
    
  } else if(enif_is_tuple(env, argv[0])) {
    /* argv[0] is tuple, should be in form {type, binary}, where type is "elf" */
    if(!enif_get_tuple(env, argv[0], &arity, &arg_tuple))
      return mk_error(env, "arg0_not_{type,binary}_tuple");
    if(arity!=2)
      return mk_error(env, "arg0_arity_not_2");
    if(!enif_get_atom(env, arg_tuple[0], binary_type, sizeof(binary_type), ERL_NIF_LATIN1))
      return mk_error(env, "arg0_tuple_first_elem_is_not_atom");
    if(!enif_is_binary(env, arg_tuple[1]))
      return mk_error(env, "arg0_tuple_second_elem_is_not_binary");
    if(!enif_inspect_binary(env, arg_tuple[1], &elf_binary))
      return enif_make_badarg(env);

    if(strcmp(binary_type, "elf"))
      return mk_error(env, "unknown_binary_type");

    char *errmsg;
    
    int rv  = load_elf(*vm, elf_binary.data, elf_binary.size, &errmsg);
    if(rv < 0){
      ebpf_destroy(*vm);
      return mk_error(env, errmsg);
    }
    
  } else {
    /* argv[0] structure is wrong */
    return mk_error(env, "arg0_not_a_binary_or_tuple");
  }


  /* Should return VM object to erlang here */
  res = enif_make_resource(env, vm);
  enif_release_resource(vm);
  return enif_make_tuple(env, 2, atom_ok, res);
}

/*
 * Run given ebpf VM with given "memory"
 */
static ERL_NIF_TERM
run(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary ebpf_memory;
    struct ebpf_vm **vm;

    if(argc != 2)
    {
        return enif_make_badarg(env);
    }

    if(!enif_get_resource(env, argv[0], EBPF_VM_RESOURCE, (void **)&vm)) {
      return mk_error(env, "ebpf_get_resource_error");
    }

    if(!enif_is_binary(env, argv[1]))
        return mk_error(env, "arg1_not_a_binary");
    if(!enif_inspect_binary(env, argv[1], &ebpf_memory))
        return enif_make_badarg(env);

    uint64_t ret;
    ret = ebpf_exec(*vm, ebpf_memory.data, ebpf_memory.size);

    return mk_ret_tuple(env, ret);
}

static ErlNifFunc nif_funcs[] = {
				 {"create", 1, create},
				 {"run", 2, run}
};

ERL_NIF_INIT(erl_ebpf, nif_funcs, load, NULL, NULL, NULL);


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
