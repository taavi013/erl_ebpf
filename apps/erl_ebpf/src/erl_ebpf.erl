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
     {"Return constant from 2 EBPF programs", ?_assert( 
					      begin
						  {ok, R1} = erl_ebpf:create(<<16#b7,0,0,0,3,0,0,0,16#95,0,0,0,0,0,0,0>>), 
						  {ok, R2} = erl_ebpf:create(<<16#b7,0,0,0,4,0,0,0,16#95,0,0,0,0,0,0,0>>),
						  erl_ebpf:run(R2, <<"b">>) =:= {ok, 4},
						  erl_ebpf:run(R1, <<"c">>) =:= {ok, 3}
					      end
					     )}, 
     {"Return first byte of binary", ?_assert( 
					      begin
						  {ok, R} = erl_ebpf:create(<<16#71,16#10,0,0,0,0,0,0,16#95,0,0,0,0,0,0,0>>), 
						  erl_ebpf:run(R, <<"ab">>) =:= {ok, $a} 
					      end
					     )},
     {"Load from ELF", ?_assert(
			  begin
			      Filename = test_file("p1.o"),
			      ?debugVal(Filename),
			      {ok, R} = erl_ebpf:create_from_elf(Filename),
			      erl_ebpf:run(R, <<"ab">>) =:= {ok, 5}
			  end
			 )}
    ].

-endif.

