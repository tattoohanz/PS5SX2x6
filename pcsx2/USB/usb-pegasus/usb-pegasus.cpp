// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

// I-O DATA USB-ET/TX (04BB:0904), an ADMtek AN986 "Pegasus" USB Ethernet adapter, for Battle Gear 3's LANEGG.IRX.
// What LANEGG does with it (static analysis of LANEGG 1.05.0 from the batlgr3 dongle; needs proper testing):
//  - control 0xC0/0xF0 GET_REGISTERS and 0x40/0xF1 SET_REGISTERS, wIndex = register, at least 2 bytes;
//  - the EEPROM through 0x20 (offset) / 0x21-0x22 (data) / 0x23 (control: 0x02 read, 0x01 write, 0x04 done);
//  - the PHY through 0x25 (address) / 0x26-0x27 (data) / 0x28 (control: 0x40 read, 0x20 write, 0x80 done, low 5 bits reg);
//  - EthCtrl1 (0x01) bit 0x08 is a reset that must clear by itself;
//  - an interface with bulk IN, bulk OUT and interrupt IN, in that order;
//  - TX (bulk OUT): u16 LE length + the frame (+1 byte when length+2 is a multiple of 64);
//  - RX (bulk IN): the frame, 4 bytes of CRC and a 4-byte trailer (status at [count-2], & 0x1F = errors), 0x44 at least;
//    LANEGG takes count-8 as the frame length.
// The network behind it is PCSX2's sockets adapter (DEV9/sockets.cpp), as the PS2's own adapter uses on the PS5: its DHCP
// gives 192.0.2.100 (gateway and DNS 192.0.2.1), its DNS answers the hosts of DEV9/Eth (EmuConfig.DEV9.EthHosts) and
// forwards the rest; TCP and UDP go out through the console's sockets. PS5SX2x6/BG3Server = a.b.c.d in the game's
// settings adds bg3.betson.com and cc3urijnamag.battlegear.net -> a.b.c.d to those hosts.

#include "USB/usb-pegasus/usb-pegasus.h"
#include "USB/qemu-usb/qusb.h"
#include "USB/qemu-usb/desc.h"
#include "USB/qemu-usb/USBinternal.h"
#include "USB/USB.h"
#include "common/Console.h"
#include "Host.h"
#include "IconsFontAwesome.h"
#include "StateWrapper.h"
#include "DEV9/sockets.h"
#include "common/StringUtil.h"
#include "common/SettingsInterface.h"

#include <algorithm>
#include <array>
#include <optional>
#include <cstring>
#include <deque>
#include <memory>
#include <vector>

namespace usb_pegasus
{
	static const uint8_t s_dev_descriptor[] = {
		0x12, 0x01, 0x10, 0x01, // bLength, DEVICE, bcdUSB 1.10
		0x00, 0x00, 0x00, 0x08, // class/subclass/protocol in the interface, bMaxPacketSize0 8
		0xBB, 0x04, 0x04, 0x09, // idVendor 0x04BB (I-O DATA), idProduct 0x0904 (USB-ET/TX)
		0x01, 0x01, 0x01, 0x02, // bcdDevice 1.01, iManufacturer 1, iProduct 2
		0x00, 0x01,             // iSerialNumber 0, bNumConfigurations 1
	};

	static const uint8_t s_config_descriptor[] = {
		0x09, 0x02, 0x27, 0x00, 0x01, 0x01, 0x00, 0x80, 0x32, // CONFIGURATION: 39 bytes, 1 interface, value 1, bus powered, 100 mA
		0x09, 0x04, 0x00, 0x00, 0x03, 0xFF, 0x00, 0xFF, 0x00, // INTERFACE 0: 3 endpoints, vendor specific
		0x07, 0x05, 0x81, 0x02, 0x40, 0x00, 0x00,             // EP1 IN bulk 64
		0x07, 0x05, 0x02, 0x02, 0x40, 0x00, 0x00,             // EP2 OUT bulk 64
		0x07, 0x05, 0x83, 0x03, 0x08, 0x00, 0x01,             // EP3 IN interrupt 8, 1 ms
	};

	static const USBDescStrings s_strings = {"", "I-O DATA", "USB-ET/TX"};

	enum : u8
	{
		REG_ETHCTRL1 = 0x01,
		REG_EPROM_OFFSET = 0x20,
		REG_EPROM_DATA = 0x21,
		REG_EPROM_CTRL = 0x23,
		REG_PHY_ADDR = 0x25,
		REG_PHY_DATA = 0x26,
		REG_PHY_CTRL = 0x28,
	};

	// The sockets adapter, with the MAC it answers to readable (ps2MAC is protected in NetAdapter).
	class PegasusNet final : public SocketAdapter
	{
	public:
		PacketReader::MAC_Address MAC() const { return ps2MAC; }
	};

	struct PegasusState
	{
		USBDevice dev{};
		USBDesc desc{};
		USBDescDevice desc_dev{};

		std::array<u8, 256> regs{};
		std::array<u16, 64> eeprom{};
		std::array<u16, 32> phy{};
		std::vector<u8> tx;              // a frame being received over several OUT packets
		std::deque<std::vector<u8>> rx;  // frames waiting for the bulk IN endpoint (wire format)
		u32 tx_logged = 0;
		u32 rx_logged = 0;
		std::array<u8, 6> mac{};
		bool redirect = false;   // router:23 (the router's telnet) <-> server:23
		std::array<u8, 4> server{};
		std::array<u8, 4> router{}; // the address the game telnets to (BG3: 192.168.1.1), learnt from its first SYN
		bool router_known = false;
		std::unique_ptr<PegasusNet> net;
	};

	static constexpr u8 kPhyAddr = 1;

	static void Reset(PegasusState* s)
	{
		s->regs.fill(0);
		// MAC 00:A0:B0 (I-O DATA's OUI) + 4D:4C:01 ("ML").
		const u8* mac = s->mac.data();
		s->eeprom.fill(0xFFFF);
		for (int i = 0; i < 3; i++)
			s->eeprom[i] = static_cast<u16>(mac[i * 2] | (mac[i * 2 + 1] << 8));
		std::memcpy(&s->regs[0x10], mac, 6);
		s->phy.fill(0);
		s->phy[0] = 0x3100; // BMCR: 100 Mb/s, autonegotiation, full duplex
		s->phy[1] = 0x782D; // BMSR: 10/100 capable, autonegotiation complete, link up
		s->phy[2] = 0x0022; // PHYID
		s->phy[3] = 0x5610;
		s->phy[4] = 0x05E1; // ANAR: 100FD/100HD/10FD/10HD
		s->phy[5] = 0x45E1; // ANLPAR: the partner the same
		s->tx.clear();
		s->rx.clear();
	}

	// A register written by the host: run what it starts.
	static void RegWritten(PegasusState* s, u8 reg)
	{
		switch (reg)
		{
			case REG_ETHCTRL1:
				s->regs[REG_ETHCTRL1] &= ~0x08; // the reset bit clears at once
				break;
			case REG_EPROM_CTRL:
			{
				const u8 ctrl = s->regs[REG_EPROM_CTRL];
				const u8 off = s->regs[REG_EPROM_OFFSET] & 0x3F;
				if (ctrl & 0x02)
				{
					s->regs[REG_EPROM_DATA] = static_cast<u8>(s->eeprom[off]);
					s->regs[REG_EPROM_DATA + 1] = static_cast<u8>(s->eeprom[off] >> 8);
				}
				else if (ctrl & 0x01)
					s->eeprom[off] = static_cast<u16>(s->regs[REG_EPROM_DATA] | (s->regs[REG_EPROM_DATA + 1] << 8));
				if (ctrl & 0x03)
					s->regs[REG_EPROM_CTRL] = (ctrl & ~0x03) | 0x04;
				break;
			}
			case REG_PHY_CTRL:
			{
				const u8 ctrl = s->regs[REG_PHY_CTRL];
				const u8 r = ctrl & 0x1F;
				const bool ours = (s->regs[REG_PHY_ADDR] & 0x1F) == kPhyAddr;
				if (ctrl & 0x40)
				{
					const u16 v = ours ? s->phy[r] : 0xFFFF;
					s->regs[REG_PHY_DATA] = static_cast<u8>(v);
					s->regs[REG_PHY_DATA + 1] = static_cast<u8>(v >> 8);
				}
				else if ((ctrl & 0x20) && ours && r != 1)
					s->phy[r] = static_cast<u16>(s->regs[REG_PHY_DATA] | (s->regs[REG_PHY_DATA + 1] << 8));
				if (ctrl & 0x60)
					s->regs[REG_PHY_CTRL] = (ctrl & ~0x60) | 0x80;
				break;
			}
		}
	}

	static void LogFrame(const char* dir, u32& count, const u8* f, size_t n)
	{
		if (n < 14)
			return;
		// The cabinets' link broadcasts (UDP 9610) come many times a second: the first 3, then every 1000th.
		static u32 s_link = 0;
		if (n >= 38 && f[12] == 0x08 && f[13] == 0x00 && f[23] == 17)
		{
			const size_t ihl0 = static_cast<size_t>(f[14] & 0x0F) * 4;
			if (n >= 14 + ihl0 + 4 && ((f[14 + ihl0 + 2] << 8) | f[14 + ihl0 + 3]) == 9610)
			{
				if (s_link++ >= 3 && (s_link % 1000) != 0)
					return;
				Console.WriteLn("PEGASUS: (link broadcast UDP 9610 #%u)", s_link);
			}
		}
		if (count >= 400)
			return;
		count++;
		const u16 type = static_cast<u16>((f[12] << 8) | f[13]);
		char extra[128] = "";
		if (type == 0x0800 && n >= 34)
		{
			const u8 proto = f[23];
			const size_t ihl = static_cast<size_t>(f[14] & 0x0F) * 4;
			if ((proto == 17 || proto == 6) && n >= 14 + ihl + 4)
			{
				const u8* l4 = f + 14 + ihl;
				char flags[16] = "";
				if (proto == 6 && n >= 14 + ihl + 14)
				{
					const u8 fl = l4[13];
					std::snprintf(flags, sizeof(flags), " [%s%s%s%s%s]", (fl & 0x02) ? "S" : "", (fl & 0x10) ? "A" : "",
						(fl & 0x08) ? "P" : "", (fl & 0x01) ? "F" : "", (fl & 0x04) ? "R" : "");
				}
				std::snprintf(extra, sizeof(extra), " %s %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u%s", proto == 17 ? "UDP" : "TCP",
					f[26], f[27], f[28], f[29], (l4[0] << 8) | l4[1], f[30], f[31], f[32], f[33], (l4[2] << 8) | l4[3], flags);
			}
			else
				std::snprintf(extra, sizeof(extra), " IP proto %u", proto);
		}
		else if (type == 0x0806 && n >= 42)
			std::snprintf(extra, sizeof(extra), " ARP who-has %u.%u.%u.%u", f[38], f[39], f[40], f[41]);
		Console.WriteLn("PEGASUS: %s %zu bytes to %02X:%02X:%02X:%02X:%02X:%02X type %04X%s", dir, n,
			f[0], f[1], f[2], f[3], f[4], f[5], type, extra);
	}

	// Internet checksum over a buffer, folded into an accumulator.
	static u32 SumBytes(u32 sum, const u8* p, size_t n)
	{
		for (size_t i = 0; i + 1 < n; i += 2)
			sum += static_cast<u32>((p[i] << 8) | p[i + 1]);
		if (n & 1)
			sum += static_cast<u32>(p[n - 1] << 8);
		return sum;
	}
	static u16 Fold(u32 sum)
	{
		while (sum >> 16)
			sum = (sum & 0xFFFF) + (sum >> 16);
		return static_cast<u16>(~sum);
	}

	// BG3 logs in to its router by telnet for the vendor ID (BG3: 192.168.1.1, a DrayTek Vigor2200x; BG3 Tuned 2.05J:
	// a YAMAHA RTA55i); send that to the server. tx: the game's TCP to router:23 goes to server:23 (the router is the
	// first address the game telnets to); rx: the server's TCP from :23 comes back as the router.
	// Rewrites the address and both checksums.
	static void RedirectTelnet(PegasusState* s, u8* f, size_t n, bool tx)
	{
		const u8* router = s->router.data();
		if (!s->redirect || n < 34 || f[12] != 0x08 || f[13] != 0x00 || f[23] != 6)
			return;
		const size_t ihl = static_cast<size_t>(f[14] & 0x0F) * 4;
		const size_t total = static_cast<size_t>((f[16] << 8) | f[17]);
		if (ihl < 20 || total < ihl + 20 || 14 + total > n)
			return;
		u8* ip = f + 14;
		u8* tcp = ip + ihl;
		u8* addr;
		if (tx)
		{
			if (((tcp[2] << 8) | tcp[3]) != 23 || std::memcmp(ip + 16, s->server.data(), 4) == 0)
				return;
			if (!s->router_known)
			{
				std::memcpy(s->router.data(), ip + 16, 4);
				s->router_known = true;
				Console.WriteLn("PEGASUS: telnet to %u.%u.%u.%u:23 (the router's vendor ID) goes to %u.%u.%u.%u:23",
					ip[16], ip[17], ip[18], ip[19], s->server[0], s->server[1], s->server[2], s->server[3]);
			}
			if (std::memcmp(ip + 16, router, 4) != 0)
				return;
			addr = ip + 16;
			std::memcpy(addr, s->server.data(), 4);
		}
		else
		{
			if (!s->router_known || std::memcmp(ip + 12, s->server.data(), 4) != 0 || ((tcp[0] << 8) | tcp[1]) != 23)
				return;
			addr = ip + 12;
			std::memcpy(addr, router, 4);
		}
		ip[10] = ip[11] = 0;
		const u16 ipsum = Fold(SumBytes(0, ip, ihl));
		ip[10] = static_cast<u8>(ipsum >> 8);
		ip[11] = static_cast<u8>(ipsum);
		const size_t tcplen = total - ihl;
		tcp[16] = tcp[17] = 0;
		u32 sum = SumBytes(0, ip + 12, 8); // source and destination
		sum += 6 + static_cast<u32>(tcplen);
		const u16 tsum = Fold(SumBytes(sum, tcp, tcplen));
		tcp[16] = static_cast<u8>(tsum >> 8);
		tcp[17] = static_cast<u8>(tsum);
	}

	static void HandleReset(USBDevice* dev)
	{
		Reset(USB_CONTAINER_OF(dev, PegasusState, dev));
	}

	static void HandleControl(USBDevice* dev, USBPacket* p, int request, int value, int index, int length, uint8_t* data)
	{
		PegasusState* s = USB_CONTAINER_OF(dev, PegasusState, dev);
		if (usb_desc_handle_control(dev, p, request, value, index, length, data) >= 0)
			return;

		const u8 reg = static_cast<u8>(index);
		switch (request)
		{
			case VendorDeviceRequest | 0xF0: // GET_REGISTERS
				for (int i = 0; i < length; i++)
					data[i] = s->regs[static_cast<u8>(reg + i)];
				p->actual_length = length;
				break;
			case VendorDeviceOutRequest | 0xF1: // SET_REGISTERS
				for (int i = 0; i < length; i++)
					s->regs[static_cast<u8>(reg + i)] = data[i];
				for (int i = 0; i < length; i++)
					RegWritten(s, static_cast<u8>(reg + i));
				break;
			case VendorDeviceOutRequest | 0xF2: // SET_REGISTER (one byte in wValue)
				s->regs[reg] = static_cast<u8>(value);
				RegWritten(s, reg);
				break;
			default:
				Console.Warning("PEGASUS: control request %04X value %04X index %04X length %d stalled", request, value, index, length);
				p->status = USB_RET_STALL;
				break;
		}
	}

	static void HandleData(USBDevice* dev, USBPacket* p)
	{
		PegasusState* s = USB_CONTAINER_OF(dev, PegasusState, dev);
		switch (p->pid)
		{
			case USB_TOKEN_OUT:
				if (p->ep->nr == 2)
				{
					const size_t old = s->tx.size();
					s->tx.resize(old + p->buffer_size);
					usb_packet_copy(p, s->tx.data() + old, p->buffer_size);
					if (s->tx.size() >= 2)
					{
						const size_t len = s->tx[0] | (s->tx[1] << 8);
						if (s->tx.size() >= len + 2 || len > 1536)
						{
							if (len <= 1536 && len >= 14)
							{
								LogFrame("TX", s->tx_logged, s->tx.data() + 2, len);
								RedirectTelnet(s, s->tx.data() + 2, len, true);
								if (s->net)
								{
									NetPacket pkt(s->tx.data() + 2, static_cast<int>(len));
									s->net->send(&pkt);
								}
							}
							s->tx.clear(); // also drops the pad byte LANEGG adds at a multiple of 64
						}
					}
				}
				else
					p->status = USB_RET_STALL;
				break;
			case USB_TOKEN_IN:
				if (p->ep->nr == 1)
				{
					// Pull what the network has for us, as the PS2 adapter's receive thread does.
					if (s->net)
					{
						NetPacket pkt;
						while (s->rx.size() < 32 && s->net->recv(&pkt))
						{
							if (pkt.size < 14 || pkt.size > 1514)
								continue;
							RedirectTelnet(s, reinterpret_cast<u8*>(pkt.buffer), static_cast<size_t>(pkt.size), false);
							LogFrame("RX", s->rx_logged, reinterpret_cast<const u8*>(pkt.buffer), static_cast<size_t>(pkt.size));
							// Wire format: the frame (at least 60 bytes), 4 bytes of CRC, the trailer
							// (length incl. CRC, low/high; status 0 = no error; 0).
							const size_t flen = std::max<size_t>(static_cast<size_t>(pkt.size), 60);
							std::vector<u8> w(flen + 8, 0);
							std::memcpy(w.data(), pkt.buffer, static_cast<size_t>(pkt.size));
							const size_t wl = flen + 4;
							w[flen + 4] = static_cast<u8>(wl);
							w[flen + 5] = static_cast<u8>((wl >> 8) & 0x0F);
							s->rx.push_back(std::move(w));
						}
					}
					if (s->rx.empty())
					{
						p->status = USB_RET_NAK;
						break;
					}
					std::vector<u8>& f = s->rx.front();
					usb_packet_copy(p, f.data(), std::min<size_t>(f.size(), p->buffer_size));
					s->rx.pop_front();
				}
				else if (p->ep->nr == 3)
				{
					// Interrupt status: nothing to report (no errors, carrier on).
					p->status = USB_RET_NAK;
				}
				else
					p->status = USB_RET_STALL;
				break;
			default:
				p->status = USB_RET_STALL;
				break;
		}
	}

	static void HandleDestroy(USBDevice* dev)
	{
		delete USB_CONTAINER_OF(dev, PegasusState, dev);
	}

	USBDevice* PegasusDevice::CreateDevice(SettingsInterface& si, u32 port, u32 subtype) const
	{
		PegasusState* s = new PegasusState();
		// bg3.betson.com -> PS5SX2x6/BG3Server, for the DNS server of the sockets adapter (it loads the hosts when made).
		const std::string server = si.GetStringValue("PS5SX2x6", "BG3Server", "");
		if (!server.empty())
		{
			std::vector<std::string_view> parts = StringUtil::SplitString(server, '.', false);
			Pcsx2Config::DEV9Options::HostEntry e{};
			bool ok = parts.size() == 4;
			for (size_t i = 0; ok && i < 4; i++)
			{
				const std::optional<u32> v = StringUtil::FromChars<u32>(parts[i]);
				ok = v.has_value() && v.value() < 256;
				if (ok)
					e.Address[i] = static_cast<u8>(v.value());
			}
			if (ok)
			{
				s->redirect = true;
				std::memcpy(s->server.data(), e.Address, 4);
				// BG3 (export): bg3.betson.com; BG3 Tuned 2.05J: cc3urijnamag.battlegear.net.
				static constexpr const char* names[] = {"bg3.betson.com", "cc3urijnamag.battlegear.net"};
				auto& hosts = EmuConfig.DEV9.EthHosts;
				for (const char* name : names)
				{
					hosts.erase(std::remove_if(hosts.begin(), hosts.end(), [name](const auto& h) { return h.Url == name; }), hosts.end());
					e.Url = name;
					e.Desc = "Battle Gear 3 NESYS";
					e.Enabled = true;
					hosts.push_back(e);
					Console.WriteLn("PEGASUS: %s -> %s (PS5SX2x6/BG3Server)", name, server.c_str());
				}
				// Hand out the internal DNS (192.0.2.1): it answers the hosts above and forwards the rest.
				EmuConfig.DEV9.ModeDNS1 = Pcsx2Config::DEV9Options::DnsMode::Internal;
				Console.WriteLn("PEGASUS: telnet to port 23 (the router's vendor ID) goes to %s:23", server.c_str());
			}
			else
				Console.Error("PEGASUS: PS5SX2x6/BG3Server \"%s\" is not an IPv4 address", server.c_str());
		}
		else
			Console.Warning("PEGASUS: no PS5SX2x6/BG3Server: bg3.betson.com goes to the real DNS");
		// The PS2's own network adapter may be off (the flag nonetwork leaves DEV9/Eth/EthDevice empty); this one is a
		// different card, so with no adapter named it takes the console's network as "Auto" does. EthEnable stays as it is.
		if (EmuConfig.DEV9.EthDevice.empty())
		{
			EmuConfig.DEV9.EthDevice = "Auto";
			Console.WriteLn("PEGASUS: DEV9/Eth/EthDevice empty (PS2 network adapter off): using Auto for the USB adapter");
		}
		s->net = std::make_unique<PegasusNet>();
		if (!s->net->isInitialised())
		{
			Console.Error("PEGASUS: the sockets adapter did not start: no network behind the adapter");
			s->net.reset();
		}
		static constexpr u8 fallback_mac[6] = {0x00, 0xA0, 0xB0, 0x4D, 0x4C, 0x01};
		if (s->net)
			std::memcpy(s->mac.data(), s->net->MAC().bytes, 6);
		else
			std::memcpy(s->mac.data(), fallback_mac, 6);
		s->dev.speed = USB_SPEED_FULL;
		s->desc.full = &s->desc_dev;
		s->desc.str = s_strings;
		if (usb_desc_parse_dev(s_dev_descriptor, sizeof(s_dev_descriptor), s->desc, s->desc_dev) < 0 ||
			usb_desc_parse_config(s_config_descriptor, sizeof(s_config_descriptor), s->desc_dev) < 0)
		{
			HandleDestroy(&s->dev);
			return nullptr;
		}
		s->dev.klass.handle_attach = usb_desc_attach;
		s->dev.klass.handle_reset = HandleReset;
		s->dev.klass.handle_control = HandleControl;
		s->dev.klass.handle_data = HandleData;
		s->dev.klass.unrealize = HandleDestroy;
		s->dev.klass.usb_desc = &s->desc;
		s->dev.klass.product_desc = s->desc.str[2];
		usb_desc_init(&s->dev);
		usb_ep_init(&s->dev);
		Reset(s);
		Console.WriteLn("PEGASUS: USB-ET/TX (04BB:0904) on USB port %u, MAC %02X:%02X:%02X:%02X:%02X:%02X, network %s", port + 1,
			s->mac[0], s->mac[1], s->mac[2], s->mac[3], s->mac[4], s->mac[5], s->net ? "sockets" : "none");
		return &s->dev;
	}

	const char* PegasusDevice::Name() const { return TRANSLATE_NOOP("USB", "USB Ethernet (Pegasus)"); }
	const char* PegasusDevice::TypeName() const { return "pegasus"; }
	const char* PegasusDevice::IconName() const { return ICON_FA_NETWORK_WIRED; }

	bool PegasusDevice::Freeze(USBDevice* dev, StateWrapper& sw) const
	{
		PegasusState* s = USB_CONTAINER_OF(dev, PegasusState, dev);
		if (!sw.DoMarker("PegasusDevice"))
			return false;
		sw.DoBytes(s->regs.data(), s->regs.size());
		sw.DoBytes(s->eeprom.data(), s->eeprom.size() * sizeof(u16));
		sw.DoBytes(s->phy.data(), s->phy.size() * sizeof(u16));
		if (sw.IsReading())
		{
			s->tx.clear();
			s->rx.clear();
		}
		return true;
	}
} // namespace usb_pegasus
