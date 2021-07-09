CC = gcc
CFLAGS ?= -DUNICODE -D_DEBUG -O2 -I.
CXXFLAGS ?= -DUNICODE -D_DEBUG -O2 -I.

installdir = ..\\dist

sources = mhook-lib\\mhook.c disasm-lib\\disasm.c disasm-lib\\disasm_x86.c disasm-lib\\cpu.c
deps = $(sources:.c=.d)
objs = $(sources:.c=.o)
archive = libmhook.a
installheader=mhook-lib\\mhook.h

testsources = mhook-test\mhook-test.cc mhook-test\stdafx.cc
testdeps = $(testsources:.cc=.d)
testobjs = $(testsources:.cc=.o)
testexe = mhook-test.exe

$(archive): $(objs)
	$(AR) -crs "$@" $^

$(deps): %.d: %.c
	@$(CC) -MM $(CPPFLAGS) $< | \
	sed "s,\($*\)\.o[ :]*,\1.o $@ : ,g" > $@

.PHONY: install
install:
	mkdir "$(installdir)\\lib" || :
	copy "$(archive)" "$(installdir)\\lib"
	mkdir "$(installdir)\\include" || :
	copy "$(installheader)" "$(installdir)\\include"

.PHONY: clean
clean:
	del $(archive) $(objs) $(deps) $(testexe) $(testdeps) $(testobjs)
	
.PHONY: test
test: $(testexe)
	$(testexe)
	
$(testexe): $(testobjs) $(archive)
	$(CC) -o $(testexe) -municode -Wl,--subsystem,console $^ -lws2_32 -lgdi32

include $(deps)
