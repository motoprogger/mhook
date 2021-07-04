CC = gcc -DUNICODE
sources = mhook-lib\\mhook.c disasm-lib\\disasm.c disasm-lib\\disasm_x86.c
deps = $(sources:.c=.d)
objs = $(sources:.c=.o)
archive = mhook.a

$(archive): $(objs)
	$(AR) -crs "$@" "$<"

$(deps): %.d: %.c
	@$(CC) -MM $(CPPFLAGS) $< | \
	sed "s,\($*\)\.o[ :]*,\1.o $@ : ,g" > $@

.PHONY: clean
clean:
	del $(archive) $(objs) $(deps)

include $(deps)
