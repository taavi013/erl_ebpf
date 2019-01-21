GLOBAL_REBAR := $(shell $(HOME)/.cache/rebar3/bin/rebar3 -v 2> /dev/null)
ifndef GLOBAL_REBAR
REBAR = $(CURDIR)/rebar3
else
REBAR = $(HOME)/.cache/rebar3/bin/rebar3
endif

all::
		$(REBAR) compile

dialyzer::
		$(REBAR) dialyzer

release::
		$(REBAR) as prod release

distrib::
		$(REBAR) as prod tar

test::
		$(REBAR) eunit

docs:
	$(REBAR) medoc
