SDKVER?=

CSNAME="-"
DISTCSNAME="-"
TARGET=rhagoletis

DEVELOPER=$(shell xcode-select --print-path)
PLATFORM=$(DEVELOPER)/Platforms/iPhoneOS.platform/Developer
SDK=$(PLATFORM)/SDKs/iPhoneOS$(SDKVER).sdk

CC=clang
ARCHS=-arch armv7 -arch armv7s -arch arm64
HOSTARCHS=-arch i386 -arch x86_64
HOSTFLAGS=-mmacosx-version-min=10.6 $(HOSTARCHS)

CFLAGS=-Wall -Wno-deprecated-declarations -isysroot $(SDK) $(ARCHS) -I./include
FRAMEWORKS=
LDFLAGS=-isysroot $(SDK) $(ARCHS)

C_SRC=main.c
OBJC_SRC=
OBJECTS=$(C_SRC:%.c=%.o)
OBJECTS+=$(OBJC_SRC:%.m=%.o)

%.o: %.c %.m
	  $(CC) $(CFLAGS) -o $@ -c $<

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJECTS)
	  $(CC) $(OBJECTS) $(LDFLAGS) $(LIBS) $(FRAMEWORKS) -o $(TARGET)
		codesign --force --sign - --entitlements entitlements.plist --timestamp=none $(TARGET)

host_test:
	$(CC) $(HOSTFLAGS) -o $(OBJECTS) -c $(C_SRC)
	$(CC) $(OBJECTS) $(HOSTFLAGS) -o $(TARGET)

clean:
	  $(RM) *.o
		$(RM) $(TARGET)
