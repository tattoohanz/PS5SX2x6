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
// forwards the rest; TCP and UDP go out through the console's sockets. Arcade/NESYSServer = a.b.c.d in the game's
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
#include "Memory.h"
#include "common/Timer.h"

#include <algorithm>
#include <array>
#include <optional>
#include <cstring>
#include <deque>
#include <memory>
#include <vector>

#ifdef _WIN32
#include "common/RedtapeWindows.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

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

	// BG3's cabinet link: every machine broadcasts UDP to port 9610 + GROUP from a port of its own and listens on
	// 9610 + GROUP. The sockets adapter binds on the host only the source port of what the game sends, so nothing
	// would listen on 9610 + GROUP and the other machines' broadcasts would be lost. Send the link broadcasts from
	// 9610 + GROUP, so that port is bound and what comes to it reaches the game. Rewrites the port and the UDP checksum.
	static void LogLinkState();
	static u16 s_link_port = 0; // 9610 + GROUP, from the game's link broadcasts
	static void UdpChecksum(const u8* ip, u8* udp, size_t room);

	static void LinkFromListenPort(u8* f, size_t n)
	{
		if (n < 42 || f[0] != 0xFF || f[1] != 0xFF || f[12] != 0x08 || f[13] != 0x00 || f[23] != 17)
			return;
		const size_t ihl = static_cast<size_t>(f[14] & 0x0F) * 4;
		const size_t total = static_cast<size_t>((f[16] << 8) | f[17]);
		if (ihl < 20 || total < ihl + 8 || 14 + total > n)
			return;
		u8* ip = f + 14;
		u8* udp = ip + ihl;
		const u16 dport = static_cast<u16>((udp[2] << 8) | udp[3]);
		if (dport < 9610 || dport > 9610 + 15)
			return;
		s_link_port = dport;
		LogLinkState();
		if (((udp[0] << 8) | udp[1]) == dport)
			return;
		static bool s_logged = false;
		if (!s_logged)
		{
			s_logged = true;
			Console.WriteLn("PEGASUS: link broadcasts from port %u go out from %u (the port the game listens on)",
				(udp[0] << 8) | udp[1], dport);
		}
		udp[0] = udp[2];
		udp[1] = udp[3];
		UdpChecksum(ip, udp, total - ihl);
	}

	// Recompute a UDP checksum (left at 0 if the packet had none, or its length doesn't fit).
	static void UdpChecksum(const u8* ip, u8* udp, size_t room)
	{
		const size_t udplen = static_cast<size_t>((udp[4] << 8) | udp[5]);
		if (udp[6] == 0 && udp[7] == 0) // no checksum
			return;
		udp[6] = udp[7] = 0;
		if (udplen < 8 || udplen > room)
			return;
		u32 sum = SumBytes(0, ip + 12, 8); // source and destination
		sum += 17 + static_cast<u32>(udplen);
		u16 usum = Fold(SumBytes(sum, udp, udplen));
		if (usum == 0)
			usum = 0xFFFF;
		udp[6] = static_cast<u8>(usum >> 8);
		udp[7] = static_cast<u8>(usum);
	}

	// Log only: the link traffic every 2 seconds, to see where the other machine's packets wait or get lost: link
	// packets sent, received per source (with the state bytes +0x0C..+0x0F of the last one, to compare with the
	// other machine's log), own ones dropped, frames handed to the game, bulk INs that found nothing, and the most
	// frames waiting for the game at once.
	namespace link_stats
	{
		struct Src
		{
			u8 ip[4]{};
			u32 count = 0;
			u8 state[4]{};
		};
		static Src s_src[4];
		static u32 s_tx = 0, s_own = 0, s_to_game = 0, s_in_empty = 0, s_in_frames = 0;
		static size_t s_max_queue = 0;
		static u8 s_sent_state[4]{};
		static Common::Timer s_timer;

		static void Sent(const u8* payload)
		{
			s_tx++;
			std::memcpy(s_sent_state, payload + 0x0C, 4);
		}
		static void Received(const u8* ip, const u8* payload)
		{
			for (Src& r : s_src)
			{
				if (r.count == 0 && r.ip[0] == 0)
					std::memcpy(r.ip, ip + 12, 4);
				if (std::memcmp(r.ip, ip + 12, 4) == 0)
				{
					r.count++;
					std::memcpy(r.state, payload + 0x0C, 4);
					return;
				}
			}
		}
		static void Flush(size_t queue)
		{
			s_max_queue = std::max(s_max_queue, queue);
			if (s_timer.GetTimeSeconds() < 2.0)
				return;
			const double t = s_timer.GetTimeSeconds();
			s_timer.Reset();
			std::string rx;
			for (const Src& r : s_src)
				if (r.ip[0])
					rx += fmt::format(" {}.{}.{}.{}: {} (state {:02X}{:02X}{:02X}{:02X})", r.ip[0], r.ip[1], r.ip[2], r.ip[3],
						r.count, r.state[0], r.state[1], r.state[2], r.state[3]);
			Console.WriteLn("PEGASUS: link %.1fs: sent %u (state %02X%02X%02X%02X), own back %u, to the game %u frames, "
							"IN %u with a frame / %u empty, most waiting %zu; received:%s",
				t, s_tx, s_sent_state[0], s_sent_state[1], s_sent_state[2], s_sent_state[3], s_own, s_to_game,
				s_in_frames, s_in_empty, s_max_queue, rx.c_str());
			s_tx = s_own = s_to_game = s_in_empty = s_in_frames = 0;
			s_max_queue = 0;
			for (Src& r : s_src)
				r.count = 0;
		}
	} // namespace link_stats

	// BG3's link packets (0x78 bytes) name their sender by the IP at +8, the game's own address. Every emulator's
	// game has the same one (192.0.2.100, the sockets adapter's), so the other machine's packets were taken for the
	// game's own and nobody else showed up. A packet that comes in gets the address it really came from at +8 (the
	// other machine's on the LAN, unique to it); the host's own broadcasts come back to it too, and with a real
	// address they would be a machine of their own, so a packet the game sent itself is dropped. Returns false to drop.
	static constexpr size_t LINK_PAYLOAD = 0x78;
	static std::array<std::array<u8, LINK_PAYLOAD>, 16> s_link_sent = {};
	static size_t s_link_sent_next = 0;

	static u8* LinkPayload(u8* f, size_t n, u8** ip_out, size_t* room_out)
	{
		if (n < 42 || f[12] != 0x08 || f[13] != 0x00 || f[23] != 17)
			return nullptr;
		const size_t ihl = static_cast<size_t>(f[14] & 0x0F) * 4;
		const size_t total = static_cast<size_t>((f[16] << 8) | f[17]);
		if (ihl < 20 || total < ihl + 8 + LINK_PAYLOAD || 14 + total > n)
			return nullptr;
		u8* udp = f + 14 + ihl;
		const u16 dport = static_cast<u16>((udp[2] << 8) | udp[3]);
		if (dport < 9610 || dport > 9610 + 15 || ((udp[4] << 8) | udp[5]) != 8 + LINK_PAYLOAD)
			return nullptr;
		*ip_out = f + 14;
		*room_out = total - ihl;
		return udp + 8;
	}

	static void LinkRecordSent(u8* f, size_t n)
	{
		u8* ip;
		size_t room;
		const u8* p = LinkPayload(f, n, &ip, &room);
		if (!p)
			return;
		std::memcpy(s_link_sent[s_link_sent_next].data(), p, LINK_PAYLOAD);
		link_stats::Sent(p);
		s_link_sent_next = (s_link_sent_next + 1) % s_link_sent.size();
	}

	static bool LinkFixReceived(u8* f, size_t n)
	{
		u8* ip;
		size_t room;
		u8* p = LinkPayload(f, n, &ip, &room);
		if (!p)
			return true;
		static u32 s_own = 0, s_fixed = 0;
		for (const auto& sent : s_link_sent)
		{
			if (std::memcmp(sent.data(), p, LINK_PAYLOAD) == 0)
			{
				link_stats::s_own++;
				if ((s_own++ % 1000) == 0)
					Console.WriteLn("PEGASUS: link packet the game sent itself came back, dropped (%u so far)", s_own);
				return false;
			}
		}
		link_stats::Received(ip, p);
		if (std::memcmp(p + 8, ip + 12, 4) != 0)
		{
			if ((s_fixed++ % 1000) == 0)
				Console.WriteLn("PEGASUS: link packet from %u.%u.%u.%u named its sender %u.%u.%u.%u, now %u.%u.%u.%u (%u so far)",
					ip[12], ip[13], ip[14], ip[15], p[8], p[9], p[10], p[11], ip[12], ip[13], ip[14], ip[15], s_fixed);
			std::memcpy(p + 8, ip + 12, 4);
			UdpChecksum(ip, ip + (static_cast<size_t>(ip[0] & 0x0F) * 4), room);
		}
		return true;
	}

	// Log only: the link packets that come in from the other machines, by source address (first 3 of each, then
	// every 1000th of all).
	static void LogLinkRx(const u8* f, size_t n)
	{
		if (n < 42 || f[12] != 0x08 || f[13] != 0x00 || f[23] != 17)
			return;
		const size_t ihl = static_cast<size_t>(f[14] & 0x0F) * 4;
		if (n < 14 + ihl + 8)
			return;
		const u8* udp = f + 14 + ihl;
		const u16 dport = static_cast<u16>((udp[2] << 8) | udp[3]);
		if (dport < 9610 || dport > 9610 + 15)
			return;
		static u32 s_ips[8] = {};
		static u32 s_counts[8] = {};
		static u32 s_all = 0;
		const u32 src = (static_cast<u32>(f[26]) << 24) | (f[27] << 16) | (f[28] << 8) | f[29];
		u32 i = 0;
		while (i < 8 && s_counts[i] && s_ips[i] != src)
			i++;
		u32 c = 0;
		if (i < 8)
		{
			s_ips[i] = src;
			c = ++s_counts[i];
		}
		s_all++;
		if (c > 3 && (s_all % 1000) != 0)
			return;
		Console.WriteLn("PEGASUS: link RX #%u from %u.%u.%u.%u:%u to port %u, %u bytes (from this address: %u)",
			s_all, f[26], f[27], f[28], f[29], (udp[0] << 8) | udp[1], dport, static_cast<unsigned>(n), c);
	}

	// Log only: BG3's own view of the cabinet link, read from the game's memory: the link flags, the 4 "machine
	// present" words and the 4 machines' entries (24 bytes each; +0x0C state, +0x14 timer, which is left out of the
	// change test). Logged when something but a timer changes, and every 240th link packet. Addresses are those of the
	// status screen ("No %d : Connect (Timer %d)"), checked against that string first.
	static void LogLinkState()
	{
		struct Layout
		{
			const char* game;
			u32 text, flags, table;
		};
		static constexpr Layout layouts[] = {
			{"BG3", 0x276230, 0x4d0da0, 0x4d0e68}, // BGRLOAD (NM00010)
			{"BG3 Tuned", 0x29bd30, 0x4fff68, 0x500030}, // BGTLOAD (NM00015)
		};
		static constexpr char text[] = "No %d : Connect (Timer %d)";
		if (!eeMem)
			return;
		const Layout* l = nullptr;
		for (const Layout& c : layouts)
			if (std::memcmp(&eeMem->Main[c.text], text, sizeof(text)) == 0)
				l = &c;
		if (!l)
			return;
		u8 now[4 + 16 + 4 * 24];
		std::memcpy(now, &eeMem->Main[l->flags], 4);
		std::memcpy(now + 4, &eeMem->Main[l->flags + 0x30], 16);
		std::memcpy(now + 20, &eeMem->Main[l->table], 4 * 24);
		u8 cmp[sizeof(now)];
		std::memcpy(cmp, now, sizeof(now));
		for (int i = 0; i < 4; i++)
			std::memset(cmp + 20 + i * 24 + 0x14, 0, 4);
		static u8 s_last[sizeof(now)] = {};
		static u32 s_calls = 0;
		const bool changed = std::memcmp(cmp, s_last, sizeof(cmp)) != 0;
		if (!changed && (++s_calls % 240) != 0)
			return;
		std::memcpy(s_last, cmp, sizeof(cmp));
		u32 flags, present[4];
		std::memcpy(&flags, now, 4);
		std::memcpy(present, now + 4, 16);
		Console.WriteLn("PEGASUS: link state (%s)%s: flags %08X, present %X %X %X %X", l->game, changed ? " changed" : "",
			flags, present[0], present[1], present[2], present[3]);
		for (int i = 0; i < 4; i++)
		{
			const u8* e = now + 20 + i * 24;
			std::string hex;
			for (int j = 0; j < 24; j++)
				hex += fmt::format("{:02X}{}", e[j], (j % 4) == 3 ? " " : "");
			Console.WriteLn("PEGASUS:   No %d: %s", i + 1, hex.c_str());
		}
	}

	// BG3's cabinet link before a race: one machine connects by TCP to the other's 9610 + GROUP (the address it has
	// from the link packets, the other machine's on the LAN). The sockets adapter only makes connections out, so on the
	// host nothing listened there and the connection was refused ("LAN error"). This listens on the host's
	// 9610 + GROUP (learnt from the link broadcasts) and carries each connection to the game as a TCP connection from
	// the other machine's address: the SYN, the data both ways and the closing are made here, and the game's side of
	// these connections doesn't go to the sockets adapter. No retransmission: the game's side is in memory here.
	namespace link_tcp
	{
#ifdef _WIN32
		using Sock = SOCKET;
		static constexpr Sock kNoSock = INVALID_SOCKET;
		static int LastError() { return WSAGetLastError(); }
		static bool WouldBlock(int e) { return e == WSAEWOULDBLOCK; }
		static void CloseSock(Sock s) { closesocket(s); }
		static void NonBlocking(Sock s)
		{
			u_long on = 1;
			ioctlsocket(s, FIONBIO, &on);
		}
#else
		using Sock = int;
		static constexpr Sock kNoSock = -1;
		static int LastError() { return errno; }
		static bool WouldBlock(int e) { return e == EWOULDBLOCK || e == EAGAIN; }
		static void CloseSock(Sock s) { close(s); }
		static void NonBlocking(Sock s)
		{
			int on = 1;
			ioctl(s, FIONBIO, &on);
		}
#endif
		static constexpr size_t kMss = 1460;

		struct Conn
		{
			Sock sock = kNoSock;
			u8 peer[4]{};
			u16 peer_port = 0;
			u32 seq = 0;        // our next sequence number to the game
			u32 acked = 0;      // what the game has acknowledged of ours
			u32 game_next = 0;  // the game's next sequence number we expect
			u32 window = 0;     // the game's receive window
			bool established = false;
			bool host_fin = false; // the other machine closed: FIN sent to the game
			bool game_fin = false; // the game closed: the host socket shut for sending
			u64 rx_bytes = 0, tx_bytes = 0;
		};

		struct State
		{
			Sock listen = kNoSock;
			u16 port = 0;
			bool failed = false;
			bool known = false; // the game's address and both MACs, from its frames
			u8 game_ip[4]{};
			u8 game_mac[6]{};
			u8 gw_mac[6]{};
			u16 ip_id = 1;
			std::vector<Conn> conns;
		};
		static State s_tcp;

		// The game's address and MAC, and the MAC it sends to off its network (the sockets adapter's), from a frame it sent.
		static void Learn(const u8* f, size_t n)
		{
			if (s_tcp.known || n < 34 || f[12] != 0x08 || f[13] != 0x00 || f[0] == 0xFF || (f[0] & 1))
				return;
			// Only a frame to an address off the game's /24: that one goes to the gateway's MAC.
			if (f[26] == 0 || std::memcmp(f + 26, f + 30, 3) == 0)
				return;
			std::memcpy(s_tcp.game_ip, f + 26, 4);
			std::memcpy(s_tcp.game_mac, f + 6, 6);
			std::memcpy(s_tcp.gw_mac, f, 6);
			s_tcp.known = true;
		}

		static void Listen(u16 port)
		{
			if (s_tcp.listen != kNoSock || s_tcp.failed)
				return;
			Sock l = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			if (l == kNoSock)
			{
				s_tcp.failed = true;
				Console.Error("PEGASUS: link TCP: no socket (%d)", LastError());
				return;
			}
			int one = 1;
			setsockopt(l, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&one), sizeof(one));
			sockaddr_in a{};
			a.sin_family = AF_INET;
			a.sin_port = htons(port);
			a.sin_addr.s_addr = htonl(INADDR_ANY);
			if (bind(l, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0 || listen(l, 4) != 0)
			{
				Console.Error("PEGASUS: link TCP: can't listen on port %u (%d)", port, LastError());
				CloseSock(l);
				s_tcp.failed = true;
				return;
			}
			NonBlocking(l);
			s_tcp.listen = l;
			s_tcp.port = port;
			Console.WriteLn("PEGASUS: link TCP: listening on port %u for the other machines", port);
		}

		// A TCP segment to the game, from conn's peer. flags: TCP flags; data: payload.
		static void Send(PegasusState* s, const Conn& c, u8 flags, const u8* data, size_t len, bool mss = false)
		{
			const size_t optlen = mss ? 4 : 0;
			const size_t tcplen = 20 + optlen + len;
			const size_t total = 20 + tcplen;
			const size_t flen = 14 + total;
			std::vector<u8> f(flen, 0);
			std::memcpy(&f[0], s_tcp.game_mac, 6);
			std::memcpy(&f[6], s_tcp.gw_mac, 6);
			f[12] = 0x08;
			u8* ip = &f[14];
			ip[0] = 0x45;
			ip[2] = static_cast<u8>(total >> 8);
			ip[3] = static_cast<u8>(total);
			const u16 id = s_tcp.ip_id++;
			ip[4] = static_cast<u8>(id >> 8);
			ip[5] = static_cast<u8>(id);
			ip[6] = 0x40; // DF
			ip[8] = 64;
			ip[9] = 6;
			std::memcpy(ip + 12, c.peer, 4);
			std::memcpy(ip + 16, s_tcp.game_ip, 4);
			const u16 ipsum = Fold(SumBytes(0, ip, 20));
			ip[10] = static_cast<u8>(ipsum >> 8);
			ip[11] = static_cast<u8>(ipsum);
			u8* t = ip + 20;
			t[0] = static_cast<u8>(c.peer_port >> 8);
			t[1] = static_cast<u8>(c.peer_port);
			t[2] = static_cast<u8>(s_tcp.port >> 8);
			t[3] = static_cast<u8>(s_tcp.port);
			const u32 seq = (flags & 0x02) ? c.seq - 1 : c.seq; // a SYN carries the sequence number before the first
			const u32 ack = c.game_next;
			for (int i = 0; i < 4; i++)
			{
				t[4 + i] = static_cast<u8>(seq >> (24 - 8 * i));
				t[8 + i] = static_cast<u8>(ack >> (24 - 8 * i));
			}
			t[12] = static_cast<u8>(((20 + optlen) / 4) << 4);
			t[13] = flags;
			t[14] = 0xFF; // window 65535
			t[15] = 0xFF;
			if (mss)
			{
				t[20] = 2;
				t[21] = 4;
				t[22] = static_cast<u8>(kMss >> 8);
				t[23] = static_cast<u8>(kMss);
			}
			if (len)
				std::memcpy(t + 20 + optlen, data, len);
			u32 sum = SumBytes(0, ip + 12, 8);
			sum += 6 + static_cast<u32>(tcplen);
			const u16 tsum = Fold(SumBytes(sum, t, tcplen));
			t[16] = static_cast<u8>(tsum >> 8);
			t[17] = static_cast<u8>(tsum);
			// Wire format, as the frames from the network (see HandleData).
			const size_t wlen = std::max<size_t>(flen, 60);
			std::vector<u8> w(wlen + 8, 0);
			std::memcpy(w.data(), f.data(), flen);
			const size_t wl = wlen + 4;
			w[wlen + 4] = static_cast<u8>(wl);
			w[wlen + 5] = static_cast<u8>((wl >> 8) & 0x0F);
			s->rx.push_back(std::move(w));
		}

		static void Drop(size_t i, const char* why)
		{
			Conn& c = s_tcp.conns[i];
			Console.WriteLn("PEGASUS: link TCP from %u.%u.%u.%u:%u closed (%s): %llu bytes to the game, %llu from it",
				c.peer[0], c.peer[1], c.peer[2], c.peer[3], c.peer_port, why,
				static_cast<unsigned long long>(c.rx_bytes), static_cast<unsigned long long>(c.tx_bytes));
			if (c.sock != kNoSock)
				CloseSock(c.sock);
			s_tcp.conns.erase(s_tcp.conns.begin() + static_cast<std::ptrdiff_t>(i));
		}

		// Called with every bulk IN: new connections, and what the other machines sent, to the game.
		static void Poll(PegasusState* s)
		{
			if (s_tcp.listen == kNoSock || !s_tcp.known)
				return;
			for (;;)
			{
				sockaddr_in a{};
				socklen_t al = sizeof(a);
				const Sock c = accept(s_tcp.listen, reinterpret_cast<sockaddr*>(&a), &al);
				if (c == kNoSock)
					break;
				NonBlocking(c);
				int one = 1;
				setsockopt(c, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&one), sizeof(one));
				Conn n;
				n.sock = c;
				const u32 addr = ntohl(a.sin_addr.s_addr);
				for (int i = 0; i < 4; i++)
					n.peer[i] = static_cast<u8>(addr >> (24 - 8 * i));
				n.peer_port = ntohs(a.sin_port);
				n.seq = 0x42470000u + (static_cast<u32>(n.peer_port) << 8) + 1; // after the SYN
				n.acked = n.seq - 1;
				Console.WriteLn("PEGASUS: link TCP from %u.%u.%u.%u:%u accepted, SYN to the game's %u.%u.%u.%u:%u",
					n.peer[0], n.peer[1], n.peer[2], n.peer[3], n.peer_port,
					s_tcp.game_ip[0], s_tcp.game_ip[1], s_tcp.game_ip[2], s_tcp.game_ip[3], s_tcp.port);
				Send(s, n, 0x02, nullptr, 0, true);
				s_tcp.conns.push_back(n);
			}
			for (size_t i = 0; i < s_tcp.conns.size();)
			{
				Conn& c = s_tcp.conns[i];
				bool dropped = false;
				while (c.established && !c.host_fin && s->rx.size() < 32)
				{
					const u32 inflight = c.seq - c.acked;
					if (inflight + kMss > c.window)
						break;
					u8 buf[kMss];
					const int r = recv(c.sock, reinterpret_cast<char*>(buf), static_cast<int>(kMss), 0);
					if (r > 0)
					{
						Send(s, c, 0x18, buf, static_cast<size_t>(r)); // PSH ACK
						c.seq += static_cast<u32>(r);
						c.rx_bytes += static_cast<u64>(r);
						continue;
					}
					if (r == 0)
					{
						Send(s, c, 0x11, nullptr, 0); // FIN ACK
						c.seq += 1;
						c.host_fin = true;
						Console.WriteLn("PEGASUS: link TCP from %u.%u.%u.%u:%u: the other machine closed, FIN to the game",
							c.peer[0], c.peer[1], c.peer[2], c.peer[3], c.peer_port);
						break;
					}
					if (!WouldBlock(LastError()))
					{
						Send(s, c, 0x14, nullptr, 0); // RST ACK
						Drop(i, "the other machine's socket failed");
						dropped = true;
					}
					break;
				}
				if (dropped)
					continue;
				if (c.host_fin && c.game_fin && c.acked == c.seq)
				{
					Drop(i, "both sides closed");
					continue;
				}
				i++;
			}
		}

		// A frame the game sent: if it belongs to one of these connections, handle it here and return true (it doesn't
		// go to the sockets adapter).
		static bool FromGame(PegasusState* s, const u8* f, size_t n)
		{
			if (s_tcp.listen == kNoSock || n < 54 || f[12] != 0x08 || f[13] != 0x00 || f[23] != 6)
				return false;
			const size_t ihl = static_cast<size_t>(f[14] & 0x0F) * 4;
			const size_t total = static_cast<size_t>((f[16] << 8) | f[17]);
			if (ihl < 20 || 14 + total > n || total < ihl + 20)
				return false;
			const u8* ip = f + 14;
			const u8* t = ip + ihl;
			if (((t[0] << 8) | t[1]) != s_tcp.port)
				return false;
			const u16 dport = static_cast<u16>((t[2] << 8) | t[3]);
			size_t i = 0;
			while (i < s_tcp.conns.size() && !(s_tcp.conns[i].peer_port == dport && std::memcmp(s_tcp.conns[i].peer, ip + 16, 4) == 0))
				i++;
			if (i == s_tcp.conns.size())
			{
				// The game's listening port, to no connection made here: the game answering one already closed.
				return true;
			}
			Conn& c = s_tcp.conns[i];
			const u8 flags = t[13];
			const u32 seq = (static_cast<u32>(t[4]) << 24) | (t[5] << 16) | (t[6] << 8) | t[7];
			const u32 ack = (static_cast<u32>(t[8]) << 24) | (t[9] << 16) | (t[10] << 8) | t[11];
			const size_t doff = static_cast<size_t>(t[12] >> 4) * 4;
			const size_t dlen = total - ihl >= doff ? total - ihl - doff : 0;
			if (flags & 0x04) // RST
			{
				Drop(i, c.established ? "the game reset it" : "the game refused it");
				return true;
			}
			if (!c.established)
			{
				if ((flags & 0x12) != 0x12) // waiting for SYN ACK
					return true;
				c.game_next = seq + 1;
				c.acked = ack;
				c.window = static_cast<u32>((t[14] << 8) | t[15]);
				c.established = true;
				Send(s, c, 0x10, nullptr, 0); // ACK
				Console.WriteLn("PEGASUS: link TCP from %u.%u.%u.%u:%u: the game accepted it",
					c.peer[0], c.peer[1], c.peer[2], c.peer[3], c.peer_port);
				return true;
			}
			if (flags & 0x10)
			{
				if (static_cast<s32>(ack - c.acked) > 0 && static_cast<s32>(ack - c.seq) <= 0)
					c.acked = ack;
				c.window = static_cast<u32>((t[14] << 8) | t[15]);
			}
			bool reply = false;
			if (dlen)
			{
				if (seq == c.game_next && !c.game_fin)
				{
					const char* d = reinterpret_cast<const char*>(t + doff);
					size_t sent = 0;
					u32 spins = 0;
					while (sent < dlen && spins < 200000)
					{
						const int w = ::send(c.sock, d + sent, static_cast<int>(dlen - sent), 0);
						if (w > 0)
						{
							sent += static_cast<size_t>(w);
							continue;
						}
						if (w < 0 && WouldBlock(LastError()))
						{
							spins++; // the other machine's socket is full for a moment
							continue;
						}
						Send(s, c, 0x14, nullptr, 0);
						Drop(i, "sending to the other machine failed");
						return true;
					}
					if (sent < dlen)
					{
						Send(s, c, 0x14, nullptr, 0);
						Drop(i, "the other machine's socket stayed full");
						return true;
					}
					c.game_next += static_cast<u32>(dlen);
					c.tx_bytes += dlen;
				}
				reply = true; // also a repeated segment: acknowledge again
			}
			if ((flags & 0x01) && seq + dlen == c.game_next && !c.game_fin)
			{
				c.game_next += 1;
				c.game_fin = true;
#ifdef _WIN32
				shutdown(c.sock, SD_SEND);
#else
				shutdown(c.sock, SHUT_WR);
#endif
				Console.WriteLn("PEGASUS: link TCP from %u.%u.%u.%u:%u: the game closed",
					c.peer[0], c.peer[1], c.peer[2], c.peer[3], c.peer_port);
				reply = true;
			}
			if (reply)
				Send(s, c, 0x10, nullptr, 0);
			if (c.host_fin && c.game_fin && c.acked == c.seq)
				Drop(i, "both sides closed");
			return true;
		}
	} // namespace link_tcp

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
								LinkFromListenPort(s->tx.data() + 2, len);
								LinkRecordSent(s->tx.data() + 2, len);
								link_tcp::Learn(s->tx.data() + 2, len);
								if (s_link_port)
									link_tcp::Listen(s_link_port);
								if (link_tcp::FromGame(s, s->tx.data() + 2, len))
								{
									// one of the other machines' connections to the game: answered here
								}
								else if (s->net)
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
					link_tcp::Poll(s);
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
							LogLinkRx(reinterpret_cast<const u8*>(pkt.buffer), static_cast<size_t>(pkt.size));
							if (!LinkFixReceived(reinterpret_cast<u8*>(pkt.buffer), static_cast<size_t>(pkt.size)))
								continue;
							// Wire format: the frame (at least 60 bytes), 4 bytes of CRC, the trailer
							// (length incl. CRC, low/high; status 0 = no error; 0).
							const size_t flen = std::max<size_t>(static_cast<size_t>(pkt.size), 60);
							std::vector<u8> w(flen + 8, 0);
							std::memcpy(w.data(), pkt.buffer, static_cast<size_t>(pkt.size));
							const size_t wl = flen + 4;
							w[flen + 4] = static_cast<u8>(wl);
							w[flen + 5] = static_cast<u8>((wl >> 8) & 0x0F);
							s->rx.push_back(std::move(w));
							link_stats::s_to_game++;
						}
					}
					link_stats::Flush(s->rx.size());
					if (s->rx.empty())
					{
						link_stats::s_in_empty++;
						p->status = USB_RET_NAK;
						break;
					}
					link_stats::s_in_frames++;
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
		// bg3.betson.com -> Arcade/NESYSServer, for the DNS server of the sockets adapter (it loads the hosts when made).
		// Arcade/NESYSServer; PS5SX2x6/BG3Server is its old name, still read when the new one is missing.
		std::string server = si.GetStringValue("Arcade", "NESYSServer", "");
		if (server.empty())
			server = si.GetStringValue("PS5SX2x6", "BG3Server", "");
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
					Console.WriteLn("PEGASUS: %s -> %s (Arcade/NESYSServer)", name, server.c_str());
				}
				// Hand out the internal DNS (192.0.2.1): it answers the hosts above and forwards the rest.
				EmuConfig.DEV9.ModeDNS1 = Pcsx2Config::DEV9Options::DnsMode::Internal;
				Console.WriteLn("PEGASUS: telnet to port 23 (the router's vendor ID) goes to %s:23", server.c_str());
			}
			else
				Console.Error("PEGASUS: Arcade/NESYSServer \"%s\" is not an IPv4 address", server.c_str());
		}
		else
			Console.Warning("PEGASUS: no Arcade/NESYSServer: the NESYS server names go to the real DNS");
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
