include $(TOPDIR)/rules.mk

PKG_NAME:=bettercap
PKG_VERSION:=2.32.0
PKG_RELEASE:=2

GO_PKG:=github.com/bettercap/bettercap

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://github.com/julianoborba/bettercap/releases/download/v2.32.0/
PKG_HASH:=4493bf3f3e003e38aca69d960c4b09536733e5c2a3db8075d88d5206c5b1caf8
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

PKG_LICENSE:=GPL-3.0
PKG_LICENSE_FILES:=LICENSE.md
PKG_MAINTAINER:=Community <community@github.com>

PKG_BUILD_DEPENDS:=golang/host
PKG_BUILD_PARALLEL:=1
PKG_USE_MIPS16:=0

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/../feeds/packages/lang/golang/golang-package.mk

CGO_CFLAGS += -mplt

define Package/bettercap/Default
  TITLE:=The Swiss Army knife for 802.11, BLE and Ethernet networks reconnaissance and MITM attacks.
  URL:=https://www.bettercap.org/
  DEPENDS:=$(GO_ARCH_DEPENDS) +libpcap +libusb-1.0 +libnetfilter-queue
endef

define Package/bettercap
$(call Package/bettercap/Default)
  SECTION:=utils
  CATEGORY:=Network
endef

define Package/bettercap/description
  Bettercap is a powerful, easily extensible and portable framework written
  in Go which aims to offer to security researchers, red teamers and reverse
  engineers an easy to use, all-in-one solution with all the features they
  might possibly need for performing reconnaissance and attacking WiFi
  networks, Bluetooth Low Energy devices, wireless HID devices and Ethernet networks.
endef

$(eval $(call GoBinPackage,bettercap))
$(eval $(call BuildPackage,bettercap))
