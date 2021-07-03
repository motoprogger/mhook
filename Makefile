CC=mingw32-gcc-4.5.0
AR=mingw32-ar
sources = mhook-lib/mhook.c disasm-lib/disasm.c disasm-lib/disasm_x86.c
deps = $(sources:.c=.d)
objs = $(sources:.c=.o)

mhook.a: $(objs)
	$(AR) -crs "$@" "$<"

$(deps): %.d: %.c
	$(CC) -MM $(CPPFLAGS) "$<" | \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' > "$@"

include $(deps)
