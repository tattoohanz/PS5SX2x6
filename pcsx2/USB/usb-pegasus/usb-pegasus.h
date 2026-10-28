// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include "USB/deviceproxy.h"

namespace usb_pegasus
{
	// I-O DATA USB-ET/TX (ADMtek AN986 "Pegasus"), the USB Ethernet adapter Battle Gear 3's LANEGG driver accepts.
	class PegasusDevice final : public DeviceProxy
	{
	public:
		USBDevice* CreateDevice(SettingsInterface& si, u32 port, u32 subtype) const override;
		const char* Name() const override;
		const char* TypeName() const override;
		const char* IconName() const override;
		bool Freeze(USBDevice* dev, StateWrapper& sw) const override;
	};
} // namespace usb_pegasus
