MODULE    = mod_authn_sso
NAME      = authn_sso
APACHECTL = apachectl
APXS      = apxs
CFLAGS    = -pedantic -Wall -Werror
DEPS      =

all: reload

reload: install restart

install: compile
	sudo $(APXS) -ia -n $(NAME) src/$(MODULE).la

compile: src/$(MODULE).la

src/$(MODULE).la: src/$(MODULE).c src/$(MODULE).h $(DEPS)
	$(APXS) -c -l sodium -Wc,"$(CFLAGS)" src/$(MODULE).c $(DEPS)

restart:
	$(APACHECTL) restart

clean:
	rm -f src/$(MODULE).[sl]*
	rm -rf src/.libs
