#-------------------------------------------------------------------------------
.SUFFIXES:
#-------------------------------------------------------------------------------

ifeq ($(strip $(DEVKITARM)),)
$(error "Please set DEVKITARM in your environment. export DEVKITARM=<path to>devkitARM")
endif

TOPDIR ?= $(CURDIR)
include $(DEVKITARM)/3ds_rules

#-------------------------------------------------------------------------------
# Project settings
#-------------------------------------------------------------------------------
TARGET          :=  3ds-certificate-ripper
BUILD           :=  build
SOURCES         :=  source
DATA            :=  data
INCLUDES        :=  include

APP_TITLE       :=  Certificate Ripper
APP_DESCRIPTION :=  Extract TLS server certificates
APP_AUTHOR      :=  hakky54

#-------------------------------------------------------------------------------
# Code generation options
#-------------------------------------------------------------------------------
ARCH    :=  -march=armv6k -mtune=mpcore -mfloat-abi=hard -mtp=soft

CFLAGS  :=  -g -Wall -O2 -mword-relocations \
            -fomit-frame-pointer -ffunction-sections \
            $(ARCH)

CFLAGS  +=  $(INCLUDE) -D__3DS__ -D_GNU_SOURCE=1

CXXFLAGS    :=  $(CFLAGS) -fno-rtti -fno-exceptions -std=gnu++17

ASFLAGS :=  -g $(ARCH)
LDFLAGS  =  -specs=3dsx.specs -g $(ARCH) -Wl,-Map,$(notdir $*.map)

# mbedTLS for TLS/certificate work; citro2d/3d for graphics; ctru for 3DS services
LIBS    :=  -lmbedtls -lmbedx509 -lmbedcrypto \
            -lcitro2d -lcitro3d -lctru -lz -lstdc++

#-------------------------------------------------------------------------------
# Library search paths
#-------------------------------------------------------------------------------
LIBDIRS :=  $(PORTLIBS) $(CTRULIB)

#-------------------------------------------------------------------------------
# No need to edit below this line
#-------------------------------------------------------------------------------
ifneq ($(BUILD),$(notdir $(CURDIR)))
#-------------------------------------------------------------------------------

export OUTPUT   :=  $(CURDIR)/$(TARGET)
export TOPDIR   :=  $(CURDIR)

export VPATH    :=  $(foreach dir,$(SOURCES),$(CURDIR)/$(dir)) \
                    $(foreach dir,$(DATA),$(CURDIR)/$(dir))

export DEPSDIR  :=  $(CURDIR)/$(BUILD)

CFILES      :=  $(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.c)))
CPPFILES    :=  $(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.cpp)))
SFILES      :=  $(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.s)))
BINFILES    :=  $(foreach dir,$(DATA),$(notdir $(wildcard $(dir)/*.*)))

ifeq ($(strip $(CPPFILES)),)
    export LD   :=  $(CC)
else
    export LD   :=  $(CXX)
endif

export OFILES_SOURCES   :=  $(CPPFILES:.cpp=.o) $(CFILES:.c=.o) $(SFILES:.s=.o)
export OFILES_BIN       :=  $(addsuffix .o,$(BINFILES))
export OFILES           :=  $(OFILES_BIN) $(OFILES_SOURCES)
export HFILES           :=  $(addsuffix .h,$(subst .,_,$(BINFILES)))

export INCLUDE  :=  $(foreach dir,$(INCLUDES),-I$(CURDIR)/$(dir)) \
                    $(foreach dir,$(LIBDIRS),-I$(dir)/include) \
                    -I$(CURDIR)/$(BUILD)

export LIBPATHS :=  $(foreach dir,$(LIBDIRS),-L$(dir)/lib)

export _3DSXDEPS := $(if $(NO_SMDH),,$(OUTPUT).smdh)

ifeq ($(strip $(ICON)),)
    icons := $(wildcard *.png)
    ifneq (,$(findstring $(TARGET).png,$(icons)))
        export APP_ICON := $(TOPDIR)/$(TARGET).png
    else
        ifneq (,$(findstring icon.png,$(icons)))
            export APP_ICON := $(TOPDIR)/icon.png
        endif
    endif
else
    export APP_ICON := $(TOPDIR)/$(ICON)
endif

ifeq ($(strip $(NO_SMDH)),)
    export _3DSXFLAGS += --smdh=$(CURDIR)/$(TARGET).smdh
endif

.PHONY: all clean

all: $(BUILD) $(DEPSDIR)
	@$(MAKE) --no-print-directory -C $(BUILD) -f $(CURDIR)/Makefile

clean:
	@echo Cleaning...
	@rm -fr $(BUILD) $(TARGET).3dsx $(TARGET).smdh $(TARGET).elf

$(BUILD):
	@[ -d $@ ] || mkdir -p $@

$(DEPSDIR):
	@[ -d $@ ] || mkdir -p $@

#-------------------------------------------------------------------------------
else
#-------------------------------------------------------------------------------

all: $(OUTPUT).3dsx

$(OUTPUT).3dsx: $(OUTPUT).elf $(_3DSXDEPS)

$(OUTPUT).elf: $(OFILES)

#-------------------------------------------------------------------------------
%.bin.o %_bin.h: %.bin
#-------------------------------------------------------------------------------
	@echo $(notdir $<)
	@$(bin2o)

-include $(DEPSDIR)/*.d

#-------------------------------------------------------------------------------
endif
#-------------------------------------------------------------------------------
