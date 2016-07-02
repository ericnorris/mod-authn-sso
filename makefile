APACHECTL=apachectl
APXS=apxs

install: src/mod_authn_sso.la

src/mod_authn_sso.la: src/mod_authn_sso.c
	$(APXS) -l sodium -cia src/mod_authn_sso.c

restart:
	$(APACHECTL) restart

reload: install restart

clean:
	-rm -f src/mod_authn_sso.o src/mod_authn_sso.lo src/mod_authn_sso.slo src/mod_authn_sso.la
	-rm -rf src/.libs
