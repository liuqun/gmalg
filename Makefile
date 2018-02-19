export IDIR LDIR DEFS

IDIR            += ./include
IDIR            += ./source/include

CFLAGS          := $(addprefix -I, $(IDIR))
CFLAGS          += $(addprefix -L, $(LDIR))
CFLAGS          += $(addprefix -D, $(DEFS))
CFLAGS          += -shared -fPIC -O2


include rule.mk
