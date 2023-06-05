HEADERS = \
	include/gmime-sq-context.h
	# include/gmime-autocrypt-store.h \
	# gmime-crypto-policy.h

# HEADERS = \
# 	include/gmime-sq-context.h \
# 	include/gmime-autocrypt-store.h \
# 	include/gmime-crypto-policy.h

RUST_SOURCES = \
	src/lib.rs \
	src/context/imp.rs \
	src/context/mod.rs \
	src/context/sq.rs
	# src/autocrypt/imp.rs \
	# src/autocrypt/mod.rs \
	# src/autocrypt/sq.rs

all: GMimeSq-0.1.gir GMimeSq-0.1.typelib

export PKG_CONFIG_PATH=$(PWD)
export GI_TYPELIB_PATH=$(PWD)
export LD_LIBRARY_PATH=$(PWD)/target/debug

target/debug/libgmime_sq.so: $(RUST_SOURCES)
	cargo build

GMimeSq-0.1.gir: target/debug/libgmime_sq.so $(HEADERS)
	g-ir-scanner -v --warn-all \
		--namespace GMimeSq --nsversion=0.1 \
		-Iinclude --c-include "gmime-sq-context.h" \
		--symbol-prefix="gmime" \
		--identifier-prefix="GMime" \
		--library=gmime_sq --library-path=target/debug \
		--include=GMime-3.0 --include=Gio-2.0 \
		--include=GObject-2.0 -pkg gobject-2.0 \
		--output $@ \
		$(HEADERS)

GMimeSq-0.1.typelib: GMimeSq-0.1.gir
	g-ir-compiler \
		--includedir=include \
		$< -o $@

clean:
	rm -f GMimeSq-0.1.typelib
	rm -f GMimeSq-0.1.gir
	rm -f GMimeSq-0.1.vapi test-vala
	rm -rf test-c
	# rm *.pc
	# rm *.pgp
	# rm *.rev
	cargo clean

run-python: GmimeSq-0.1.typelib
	python3 test.py

run-gjs: Sq-0.1.typelib
	gjs test.js

run-vala: test-vala
	./test-vala

test-c: test.c target/debug/libgmime_sq.so GMimeSq-0.1.pc $(HEADERS)
	$(CC) -g -Wall $< `pkg-config --cflags --libs GMimeSq-0.1 gmime-3.0` -o $@

run-c: test-c
	# include a reference test using gpg?
	# ./updatekeys.sh
	@echo "========Sequia Message========"
	./test-c
	@echo "================================="

check:
	cargo test

check-bindings: target/debug/libgmime_sq.so
	cargo test --features=bindings

check-all: check check-bindings run-c run-python run-gjs run-vala
