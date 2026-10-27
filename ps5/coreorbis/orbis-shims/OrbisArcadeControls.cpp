// PS5SX2x6: player 1's DualSense on the arcade games' JVS board, one table per game (see OrbisArcadeControls.h).
#include "OrbisArcadeControls.h"

#include "Config.h"
#include "DEV9/ACJV.h"

#include <algorithm>
#include <cstdio>
#include <cstring>

namespace orbis_arcade
{
namespace
{
// main-boot.cpp's OrbisPadData button bits.
constexpr uint32_t kL3 = 0x2, kR3 = 0x4, kOptions = 0x8, kUp = 0x10, kRight = 0x20, kDown = 0x40, kLeft = 0x80, kL2 = 0x100,
				   kR2 = 0x200, kL1 = 0x400, kR1 = 0x800, kTriangle = 0x1000, kCircle = 0x2000, kCross = 0x4000, kSquare = 0x8000,
				   kTouchpad = 0x100000;

constexpr int kStickDeadzone = 10; // of 128, as the driving mapping had
constexpr uint8_t kHalf = 128;      // a trigger or a stick direction "held" past half way

uint32_t Bit(Src s)
{
	switch (s)
	{
		case Src::Cross: return kCross;
		case Src::Circle: return kCircle;
		case Src::Square: return kSquare;
		case Src::Triangle: return kTriangle;
		case Src::L1: return kL1;
		case Src::R1: return kR1;
		case Src::L2: return kL2;
		case Src::R2: return kR2;
		case Src::L3: return kL3;
		case Src::R3: return kR3;
		case Src::Options: return kOptions;
		case Src::Touchpad: return kTouchpad;
		case Src::Up: return kUp;
		case Src::Down: return kDown;
		case Src::Left: return kLeft;
		case Src::Right: return kRight;
		default: return 0;
	}
}

// pcsx2x6's default pad binding (GenericInputBinding) as a DualSense control; for a stick, `dir` gets the direction
// (0 up, 1 down, 2 left, 3 right). False for none (Unknown).
bool FromGeneric(GenericInputBinding g, Src& src, int& dir)
{
	dir = -1;
	switch (g)
	{
		case GenericInputBinding::Cross: src = Src::Cross; return true;
		case GenericInputBinding::Circle: src = Src::Circle; return true;
		case GenericInputBinding::Square: src = Src::Square; return true;
		case GenericInputBinding::Triangle: src = Src::Triangle; return true;
		case GenericInputBinding::L1: src = Src::L1; return true;
		case GenericInputBinding::R1: src = Src::R1; return true;
		case GenericInputBinding::L2: src = Src::L2; return true;
		case GenericInputBinding::R2: src = Src::R2; return true;
		case GenericInputBinding::L3: src = Src::L3; return true;
		case GenericInputBinding::R3: src = Src::R3; return true;
		case GenericInputBinding::Start: src = Src::Options; return true;
		case GenericInputBinding::Select: src = Src::Touchpad; return true;
		case GenericInputBinding::DPadUp: src = Src::Up; return true;
		case GenericInputBinding::DPadDown: src = Src::Down; return true;
		case GenericInputBinding::DPadLeft: src = Src::Left; return true;
		case GenericInputBinding::DPadRight: src = Src::Right; return true;
		case GenericInputBinding::LeftStickUp: src = Src::LeftStick; dir = 0; return true;
		case GenericInputBinding::LeftStickDown: src = Src::LeftStick; dir = 1; return true;
		case GenericInputBinding::LeftStickLeft: src = Src::LeftStick; dir = 2; return true;
		case GenericInputBinding::LeftStickRight: src = Src::LeftStick; dir = 3; return true;
		case GenericInputBinding::RightStickUp: src = Src::RightStick; dir = 0; return true;
		case GenericInputBinding::RightStickDown: src = Src::RightStick; dir = 1; return true;
		case GenericInputBinding::RightStickLeft: src = Src::RightStick; dir = 2; return true;
		case GenericInputBinding::RightStickRight: src = Src::RightStick; dir = 3; return true;
		default: return false;
	}
}

// A stick's direction held past half way (0 up, 1 down, 2 left, 3 right); x, y are 0..255 with 128 at rest.
bool StickDir(uint8_t x, uint8_t y, int dir)
{
	switch (dir)
	{
		case 0: return y < kHalf - 64;
		case 1: return y > kHalf + 63;
		case 2: return x < kHalf - 64;
		case 3: return x > kHalf + 63;
		default: return false;
	}
}

// -1..1 from a stick axis (0..255), with the dead zone taken off.
float StickAxis(uint8_t v)
{
	const int d = static_cast<int>(v) - 128;
	if (d > kStickDeadzone)
		return std::min(1.0f, (d - kStickDeadzone) / (127.0f - kStickDeadzone));
	if (d < -kStickDeadzone)
		return -std::min(1.0f, (-d - kStickDeadzone) / (128.0f - kStickDeadzone));
	return 0.0f;
}

const char* ModeName(JVS_MODE m)
{
	switch (m)
	{
		case JVS_MODE::DRIVE: return "driving";
		case JVS_MODE::FIGHTING: return "fighting";
		case JVS_MODE::STANDARD: return "buttons";
		case JVS_MODE::LIGHTGUN: return "gun";
		case JVS_MODE::DRUM: return "drum";
		case JVS_MODE::TOUCH: return "touch";
		case JVS_MODE::TWINSTICK: return "twin levers";
		default: return "unknown";
	}
}
} // namespace

const char* SrcName(Src s)
{
	switch (s)
	{
		case Src::Cross: return "Cross";
		case Src::Circle: return "Circle";
		case Src::Square: return "Square";
		case Src::Triangle: return "Triangle";
		case Src::L1: return "L1";
		case Src::R1: return "R1";
		case Src::L2: return "L2";
		case Src::R2: return "R2";
		case Src::L3: return "L3";
		case Src::R3: return "R3";
		case Src::Options: return "Options";
		case Src::Touchpad: return "Touchpad";
		case Src::Up: return "D-pad up";
		case Src::Down: return "D-pad down";
		case Src::Left: return "D-pad left";
		case Src::Right: return "D-pad right";
		case Src::DPad: return "D-pad";
		case Src::LeftStick: return "Left stick";
		case Src::RightStick: return "Right stick";
	}
	return "?";
}

bool Held(const Pad& pad, Src src)
{
	switch (src)
	{
		case Src::L2: return pad.l2 >= kHalf || (pad.buttons & kL2);
		case Src::R2: return pad.r2 >= kHalf || (pad.buttons & kR2);
		case Src::DPad: return (pad.buttons & (kUp | kDown | kLeft | kRight)) != 0;
		case Src::LeftStick:
			for (int d = 0; d < 4; d++)
				if (StickDir(pad.lx, pad.ly, d))
					return true;
			return false;
		case Src::RightStick:
			for (int d = 0; d < 4; d++)
				if (StickDir(pad.rx, pad.ry, d))
					return true;
			return false;
		default: return (pad.buttons & Bit(src)) != 0;
	}
}

GameControls ControlsFor(const std::string& gameid)
{
	const JVS_MODE mode = ACJV::ResolveModeFromGameId(gameid);
	GameControls g;
	g.mode = ModeName(mode);
	auto add = [&g](Src src, Act act, uint16_t mask, std::string label, bool system) -> Control& {
		Control c;
		c.src = src;
		c.act = act;
		c.mask = mask;
		c.label = std::move(label);
		c.system = system;
		g.rows.push_back(std::move(c));
		return g.rows.back();
	};
	auto uses = [&g](Src src) {
		return std::any_of(g.rows.begin(), g.rows.end(), [src](const Control& c) { return c.src == src; });
	};
	auto has_bit = [&g](uint16_t bit) {
		return std::any_of(g.rows.begin(), g.rows.end(), [bit](const Control& c) {
			return c.act == Act::Button && ((c.mask & bit) || std::any_of(std::begin(c.dir_mask), std::end(c.dir_mask),
																		  [bit](uint16_t m) { return (m & bit) != 0; }));
		});
	};
	// A layout's buttons, each on the pad button pcsx2x6 gives it by default.
	auto add_layout = [&](std::span<const InputBindingInfo> buttons) {
		for (const InputBindingInfo& bi : buttons)
		{
			Src src;
			int dir;
			if (FromGeneric(bi.generic_mapping, src, dir) && dir < 0)
				add(src, Act::Button, bi.bind_index, bi.display_name, false);
		}
	};
	// The lever on the D-pad (and the left stick, when it is free): JVS up, down, left, right.
	auto add_lever = [&](Src src, const char* label, bool system) {
		Control& c = add(src, Act::Button, 0, label, system);
		c.dir_mask[0] = JVS_BTN_UP;
		c.dir_mask[1] = JVS_BTN_DOWN;
		c.dir_mask[2] = JVS_BTN_LEFT;
		c.dir_mask[3] = JVS_BTN_RIGHT;
	};

	switch (mode)
	{
		case JVS_MODE::DRIVE:
		{
			add(Src::LeftStick, Act::Steer, 0, "Steering", false);
			add(Src::R2, Act::Gas, 0, "Gas", false);
			add(Src::L2, Act::Brake, 0, "Brake", false);
			add_layout(ACJV::GetRacingButtonsFor(gameid));
			// The menus' up and down (Wangan, Ridge Racer V: the test menu's SELECT), unless the layout wires them (Battle Gear 3).
			if (!has_bit(JVS_BTN_UP) && !has_bit(JVS_BTN_DOWN))
				add_lever(Src::DPad, "Menu", true);
			break;
		}
		case JVS_MODE::FIGHTING:
		case JVS_MODE::STANDARD:
		{
			add_layout(mode == JVS_MODE::FIGHTING ? ACJV::GetFightingButtonsFor(gameid) : ACJV::GetStandardButtonsFor(gameid));
			// Inufuku 2 answers on the direction bits: no lever there.
			if (!has_bit(JVS_BTN_UP))
			{
				add_lever(Src::DPad, "Lever", false);
				add_lever(Src::LeftStick, "Lever", false);
			}
			break;
		}
		case JVS_MODE::TWINSTICK:
		{
			// Zoids: the levers' directions and the triggers on their own switch bits (pcsx2x6's twin-stick table).
			int lever[2] = {-1, -1}; // the rows' indexes (more rows are added meanwhile)
			for (const InputBindingInfo& bi : ACJV::GetTwinstickBindings())
			{
				Src src;
				int dir;
				if (!FromGeneric(bi.generic_mapping, src, dir) || bi.bind_index == JVS_BTN_START || bi.bind_index == JVS_BTN_SERVICE)
					continue;
				if (dir >= 0)
				{
					int& i = lever[src == Src::RightStick ? 1 : 0];
					if (i < 0)
					{
						add(src, Act::Button, 0, src == Src::RightStick ? "Right lever" : "Left lever", false);
						i = static_cast<int>(g.rows.size()) - 1;
					}
					g.rows[static_cast<size_t>(i)].dir_mask[dir] = bi.bind_index;
				}
				else
				{
					std::string label = bi.display_name; // "P1 Left Trigger": the cabinet has one player's set
					if (label.starts_with("P1 "))
						label.erase(0, 3);
					add(src, Act::Button, bi.bind_index, std::move(label), false);
				}
			}
			break;
		}
		case JVS_MODE::DRUM:
		{
			// Taiko: the drum's player 1 sensors (pcsx2x6's channels), as a pad plays the PS2 ports: the face (Don) on
			// the D-pad's left and Circle, the rim (Ka) on L1 and R1.
			for (const InputBindingInfo& bi : ACJV::GetDrumBindings())
			{
				const std::string_view n(bi.name);
				if (n == "P1_DonLeft")
					add(Src::Left, Act::Drum, bi.bind_index, "Don (left)", false);
				else if (n == "P1_DonRight")
					add(Src::Circle, Act::Drum, bi.bind_index, "Don (right)", false);
				else if (n == "P1_KaLeft")
					add(Src::L1, Act::Drum, bi.bind_index, "Ka (left)", false);
				else if (n == "P1_KaRight")
					add(Src::R1, Act::Drum, bi.bind_index, "Ka (right)", false);
			}
			break;
		}
		case JVS_MODE::TOUCH:
		{
			add(Src::LeftStick, Act::TouchAim, 0, "Point", false);
			add(Src::Cross, Act::TouchPress, 0, "Touch", false);
			g.note = "No pointer is drawn on the screen yet, and no card reader is emulated.";
			break;
		}
		case JVS_MODE::LIGHTGUN:
		{
			const GunMapping* gm = ACJV::GetGunMappingFor(gameid);
			add(Src::LeftStick, Act::GunAim, 0, "Aim", false);
			add(Src::R2, Act::GunTrigger, gm ? gm->p1_trigger : 0, "Trigger", false);
			if (gm && gm->board == GunBoardModel::CameraVN)
				add(Src::L2, Act::GunPedal, 0, "Reload", false); // Vampire Night: no pedal; aiming off the screen reloads
			else if (gm && gm->pedal)
				add(Src::L2, Act::GunPedal, gm->pedal, "Pedal", false);
			if (gm && gm->p1_start)
				add(Src::Options, Act::Button, gm->p1_start, "Start", true);
			g.note = "No crosshair is drawn on the screen yet.";
			break;
		}
		default:
		{
			// No table in pcsx2x6: its plain player 1 buttons.
			for (const InputBindingInfo& bi : ACJV::GetButtonBindings())
			{
				const std::string_view n(bi.name);
				Src src;
				int dir;
				if (n.starts_with("P1_Button") && FromGeneric(bi.generic_mapping, src, dir) && dir < 0)
					add(src, Act::Button, bi.bind_index, bi.display_name, false);
			}
			add_lever(Src::DPad, "Lever", false);
			g.note = "pcsx2x6 has no controls table for this game.";
			break;
		}
	}

	// The cabinet's own: Start (unless the gun game has its own), the test menu's Enter (Button 1, on the first of Cross,
	// Square, Triangle, Circle, L1 and R1 the game leaves free, when its layout has no Button 1), Service, a coin and the
	// Test switch.
	if (!uses(Src::Options))
		add(Src::Options, Act::Button, JVS_BTN_START, "Start", true);
	if (!has_bit(JVS_BTN_1))
	{
		for (Src src : {Src::Cross, Src::Square, Src::Triangle, Src::Circle, Src::L1, Src::R1})
		{
			if (!uses(src))
			{
				add(src, Act::Button, JVS_BTN_1, "Enter", true);
				break;
			}
		}
	}
	add(Src::Touchpad, Act::Button, JVS_BTN_SERVICE, "Service", true);
	add(Src::L3, Act::Coin, 0, "Coin", true);
	add(Src::R3, Act::Test, 0, "Test", true);
	return g;
}

void Apply(const Pad& pad)
{
	static std::string s_game;
	static GameControls s_controls;
	static uint32_t s_prev_buttons = 0;
	static uint16_t s_prev_mask = 0;
	static uint32_t s_prev_drum = 0;
	static bool s_logged_steer = false, s_logged_gas = false, s_logged_brake = false;
	const std::string& game = ACJV::GetGameId();
	if (game != s_game)
	{
		s_game = game;
		s_controls = ControlsFor(game);
		s_prev_mask = 0;
		s_prev_drum = 0;
		std::string line;
		for (const Control& c : s_controls.rows)
			line += std::string(line.empty() ? "" : " | ") + SrcName(c.src) + " " + c.label;
		std::printf("[jvs] %s (%s, JVS mode %d): %s\n", game.c_str(), s_controls.mode.c_str(), static_cast<int>(ACJV::GetMode()),
			line.c_str());
		if (!s_controls.note.empty())
			std::printf("[jvs] %s: %s\n", game.c_str(), s_controls.note.c_str());
		std::fflush(stdout);
	}

	const uint32_t b = pad.buttons;
	const uint32_t pressed = b & ~s_prev_buttons;
	const bool l3 = (b & kL3) != 0, r3 = (b & kR3) != 0;
	uint16_t mask = 0;
	uint32_t drum = 0;
	for (const Control& c : s_controls.rows)
	{
		switch (c.act)
		{
			case Act::Button:
				if (c.src == Src::DPad)
				{
					static constexpr uint32_t dirs[4] = {kUp, kDown, kLeft, kRight};
					for (int d = 0; d < 4; d++)
						if (b & dirs[d])
							mask |= c.dir_mask[d];
				}
				else if (c.src == Src::LeftStick || c.src == Src::RightStick)
				{
					for (int d = 0; d < 4; d++)
						if (c.src == Src::LeftStick ? StickDir(pad.lx, pad.ly, d) : StickDir(pad.rx, pad.ry, d))
							mask |= c.dir_mask[d];
				}
				else if (Held(pad, c.src))
					mask |= c.mask;
				break;
			case Act::Steer:
			{
				const float x = StickAxis(pad.lx);
				ACJV::SetWheelAxis(0, x > 0.0f ? x : 0.0f);
				ACJV::SetWheelAxis(1, x < 0.0f ? -x : 0.0f);
				if (!s_logged_steer && (x > 0.5f || x < -0.5f))
				{
					std::printf("[jvs] steering: %s (left stick x %u)\n", x > 0 ? "right" : "left", pad.lx);
					s_logged_steer = true;
				}
				break;
			}
			case Act::Gas:
				ACJV::SetWheelAxis(2, pad.r2 / 255.0f);
				if (!s_logged_gas && pad.r2 > 128)
				{
					std::printf("[jvs] accelerator: R2 %u\n", pad.r2);
					s_logged_gas = true;
				}
				break;
			case Act::Brake:
				ACJV::SetWheelAxis(3, pad.l2 / 255.0f);
				if (!s_logged_brake && pad.l2 > 128)
				{
					std::printf("[jvs] brake: L2 %u\n", pad.l2);
					s_logged_brake = true;
				}
				break;
			case Act::Drum:
				if (Held(pad, c.src))
					drum |= 1u << c.mask;
				break;
			case Act::TouchAim:
			{
				const float x = StickAxis(pad.lx), y = StickAxis(pad.ly);
				ACJV::SetTouchRelativeActive(true);
				ACJV::SetTouchRelativeAxis(0, x < 0.0f ? -x : 0.0f);
				ACJV::SetTouchRelativeAxis(1, x > 0.0f ? x : 0.0f);
				ACJV::SetTouchRelativeAxis(2, y < 0.0f ? -y : 0.0f);
				ACJV::SetTouchRelativeAxis(3, y > 0.0f ? y : 0.0f);
				break;
			}
			case Act::TouchPress:
				ACJV::SetTouchPressBound(true);
				ACJV::SetTouchPressed(Held(pad, c.src));
				break;
			case Act::GunAim:
				// The stick across the picture, a little past its edges at full tilt (aiming off the screen reloads).
				ACJV::SetGunAimSource(0, true);
				ACJV::SetGunRelativeAim(0, 0.5f + 0.55f * StickAxis(pad.lx), 0.5f + 0.55f * StickAxis(pad.ly));
				break;
			case Act::GunTrigger:
				if (Held(pad, c.src))
					mask |= c.mask;
				break;
			case Act::GunPedal:
				if (c.mask)
				{
					if (Held(pad, c.src))
						mask |= c.mask;
				}
				else
					ACJV::SetGunForceOffscreen(Held(pad, c.src));
				break;
			case Act::Coin:
				if ((pressed & kL3) && !r3)
				{
					ACJV::InsertCoin(0);
					std::printf("[jvs] coin (L3): %d credit(s) inserted on slot 1 so far\n", static_cast<int>(ACJV::coin[0]));
				}
				break;
			case Act::Test:
				if ((pressed & kR3) && !l3)
				{
					ACJV::ToggleDIPSwitchState(0);
					std::printf("[jvs] test switch (R3): %s\n", ACJV::GetDIPSwitchState(0) ? "on" : "off");
				}
				break;
		}
	}
	if (const uint16_t up = s_prev_mask & ~mask)
		ACJV::SetButtonState(0, up, false);
	if (const uint16_t down = mask & ~s_prev_mask)
	{
		ACJV::SetButtonState(0, down, true);
		std::printf("[jvs] pressed: mask %04x (buttons %08x)\n", down, b);
	}
	s_prev_mask = mask;
	if (drum != s_prev_drum)
	{
		for (uint32_t ch = 0; ch < JVS_DRUM_CHANNEL_MAX; ch++)
			if (((drum ^ s_prev_drum) >> ch) & 1u)
				ACJV::SetDrumHit(ch, ((drum >> ch) & 1u) != 0);
		std::printf("[jvs] drum: channels %02x\n", drum);
		s_prev_drum = drum;
	}
	if (pressed)
		std::fflush(stdout);
	s_prev_buttons = b;
}
} // namespace orbis_arcade
