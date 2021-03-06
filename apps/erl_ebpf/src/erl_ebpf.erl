-module(erl_ebpf).
-export([create_from_elf/1, create/1, run/2]).
-on_load(init/0).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-define(APPNAME, erl_ebpf).
-define(LIBNAME, erl_ebpf).

create_from_elf(Filename) ->
    {ok, Binary} = file:read_file(Filename),
    create({elf, Binary}).

create(_) ->
    not_loaded(?LINE).

run(_, _) ->
    not_loaded(?LINE).

init() ->
    SoName = case code:priv_dir(?APPNAME) of
        {error, bad_name} ->
            case filelib:is_dir(filename:join(["..", priv])) of
                true ->
                    filename:join(["..", priv, ?LIBNAME]);
                _ ->
                    filename:join([priv, ?LIBNAME])
            end;
        Dir ->
            filename:join(Dir, ?LIBNAME)
    end,
    erlang:load_nif(SoName, 0).

not_loaded(Line) ->
    erlang:nif_error({not_loaded, [{module, ?MODULE}, {line, Line}]}).

-ifdef(EUNIT).
test_file(Filename) ->
    FullFilename = case code:priv_dir(?APPNAME) of
		       {error, bad_name} ->
			   throw(bad_name);
		       Dir ->
			   filename:join([Dir, "../test/", Filename])
		   end,
    FullFilename.

ebpf_test_() ->
    [
     {"Return constant from EBPF program", ?_assert( 
					      begin
						  {ok, R} = erl_ebpf:create(<<16#b7,0,0,0,3,0,0,0,16#95,0,0,0,0,0,0,0>>), 
						  erl_ebpf:run(R, <<"b">>) =:= {ok, 3} 
					      end
					     )},
     {"Return constant from 2 EBPF programs", ?_assertMatch([{ok,4},{ok,3}], 
							    begin
								{ok, R1} = erl_ebpf:create(<<16#b7,0,0,0,3,0,0,0,16#95,0,0,0,0,0,0,0>>), 
								{ok, R2} = erl_ebpf:create(<<16#b7,0,0,0,4,0,0,0,16#95,0,0,0,0,0,0,0>>),
								[erl_ebpf:run(R2, <<"b">>),
								 erl_ebpf:run(R1, <<"c">>)]
					      end
					     )}, 
     {"Return first byte of binary", ?_assert( 
					      begin
						  {ok, R} = erl_ebpf:create(<<16#71,16#10,0,0,0,0,0,0,16#95,0,0,0,0,0,0,0>>), 
						  erl_ebpf:run(R, <<"ab">>) =:= {ok, $a} 
					      end
					     )},
     {"Load from ELF", ?_assertMatch({ok,5}, 
				     begin
					 Filename = test_file("p1.o"),
					 ?debugVal(Filename),
					 {ok, R} = erl_ebpf:create_from_elf(Filename),
					 erl_ebpf:run(R, <<"ab">>)
				     end
				    )},
     {"Load from ELF + memfrob", ?_assertMatch({ok, 16#807060504030201}, 
					       begin
						   Filename = test_file("p5.o"),
						   ?debugVal(Filename),
						   {ok, R} = erl_ebpf:create_from_elf(Filename),
						   erl_ebpf:run(R, <<"ab">>)
					       end
			 )}

    ].

ebpf_dns_test() ->
    EbpfFilename = test_file("p6.o"),
    {ok, VM} = erl_ebpf:create_from_elf(EbpfFilename),
    Packet = <<16#60,16#0c,16#5f,16#52,16#00,16#29,16#11,16#40,
	       16#20,16#01,16#15,16#30,16#00,16#10,16#04,16#99,
	       16#0c,16#3c,16#f9,16#98,16#f8,16#c3,16#d0,16#4b,
	       16#26,16#20,16#01,16#19,16#00,16#35,16#00,16#00,
	       16#00,16#00,16#00,16#00,16#00,16#00,16#00,16#35,
	       16#e5,16#cf,16#00,16#35,16#00,16#29,16#56,16#e6,
	       16#00,16#5c,16#01,16#00,16#00,16#01,16#00,16#00,
	       16#00,16#00,16#00,16#00,16#03,16#77,16#77,16#77,
	       16#08,16#67,16#72,16#65,16#65,16#6e,16#6c,16#61,
	       16#62,16#02,16#65,16#65,16#00,16#00,16#01,16#00,
	       16#01>>,
    R = erl_ebpf:run(VM, Packet),
    ?debugVal(R).
-endif.

