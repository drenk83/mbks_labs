CXX = clang++
OUT ?= ../../work/plugins/lab4-msadpcm-tidy.so

CXXFLAGS ?= -std=c++17 -O2 -fPIC -shared
LDLIBS ?= -lclang-cpp -lLLVM
# Символы clang-tidy (ClangTidyCheck и реестр модулей) берутся из бинарника
# clang-tidy при загрузке плагина через --load.
LDFLAGS ?= -Wl,--unresolved-symbols=ignore-all

all: $(OUT)

$(OUT): MsadpcmBlockCheck.cpp
	mkdir -p $(dir $(OUT))
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS) $(LDLIBS)

clean:
	rm -f $(OUT)

.PHONY: all clean
