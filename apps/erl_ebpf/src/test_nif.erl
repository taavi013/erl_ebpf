-module(test_nif).
-export([ebpf_run/2]).
-on_load(init/0).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-define(APPNAME, erl_ebpf).
-define(LIBNAME, erl_ebpf).

ebpf_run(_, _) ->
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
    exit({not_loaded, [{module, ?MODULE}, {line, Line}]}).

-ifdef(EUNIT).
ebpf_test_() ->
    [
     {"Return constant from EBPF program", ?_assert( test_nif:ebpf_run(<<16#b7,0,0,0,3,0,0,0,16#95,0,0,0,0,0,0,0>>, <<"b">>) =:= {ok, 3} )}
    ].

-endif.

