SO_LOCATION = ../../target/debug
SIZES = 512 768 1024
FRAMES = encaps_key decaps_key ciphertext encaps decaps keygen
# should derive SONAME somehow, e.g. from CARGO_PKG_VERSION_MAJOR
SONAME = 0

BASELINES=$(foreach sz, $(SIZES), baseline-$(sz))
CHECKS=$(foreach sz, $(SIZES), runtest-$(sz))

check: $(CHECKS)

$(SO_LOCATION)/libfips203.so.$(SONAME): $(SO_LOCATION)/libfips203.so
	ln -s $< $@

runtest-%: baseline-% $(SO_LOCATION)/libfips203.so.$(SONAME)
	LD_LIBRARY_PATH=$(SO_LOCATION) ./$<

baseline-%: baseline.c ../fips203.h
	$(CC) -o $@ -g -D MLKEM_size=$* $(foreach v, $(FRAMES),-D MLKEM_$(v)=ml_kem_$*_$(v)) -Werror -Wall -pedantic -L $(SO_LOCATION) $< -Wall -lfips203

clean:
	rm -f $(BASELINES)

.PHONY: clean check
