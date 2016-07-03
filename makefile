MODULE    = mod_authn_sso
NAME      = authn_sso
APACHECTL = apachectl
APXS      = apxs
CFLAGS    = -pedantic -Wall -Werror

all: reload

reload: install restart

install: compile
	$(APXS) -ia -n $(NAME) src/$(MODULE).la

compile: src/$(MODULE).la

src/$(MODULE).la: src/$(MODULE).c
	$(APXS) -c -l sodium -Wc,"$(CFLAGS)" src/$(MODULE).c

restart:
	$(APACHECTL) restart

clean:
	rm -f src/$(MODULE).[sl]*
	rm -rf src/.libs
