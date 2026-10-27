// PS5SX2x6: player 1's DualSense on the arcade games' JVS board (pcsx2x6's DEV9/ACJV), one table per game.
//
// ControlsFor(gameid) builds a game's rows from pcsx2x6's own tables: its layout's buttons with the pad buttons pcsx2x6
// gives them by default (the game's PS2 port), the wheel and pedals of the driving games, the drum of Taiko, the touch
// panel, the gun, the twin levers of Zoids; and the cabinet's system controls (Start, coin, Test, Service, the test
// menu's Enter). Apply() feeds the running game's rows to the board; the shelf's Controls page shows the same rows, so it
// says what each button does now.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace orbis_arcade
{
// The DualSense controls a row can come from.
enum class Src : uint8_t
{
	Cross,
	Circle,
	Square,
	Triangle,
	L1,
	R1,
	L2,
	R2,
	L3,
	R3,
	Options,
	Touchpad,
	Up,
	Down,
	Left,
	Right,
	DPad,       // the four directions together (the lever)
	LeftStick,  // the stick as a whole (steering, aim, a lever)
	RightStick,
};

// What a row does with it.
enum class Act : uint8_t
{
	Button,     // JVS switch bits `mask` (a stick or the D-pad: the directions' bits in dir_mask)
	Steer,      // the left stick's X: wheel channels 0 (right) and 1 (left)
	Gas,        // wheel channel 2
	Brake,      // wheel channel 3
	Drum,       // drum channel `mask`
	TouchAim,   // the touch panel's point, the stick across the screen
	TouchPress, // touching the panel
	GunAim,     // the gun's point, the stick across the screen
	GunTrigger, // the gun's trigger bit (`mask`)
	GunPedal,   // the pedal bit (`mask`), or Vampire Night's aim-off-screen reload (mask 0)
	Coin,       // a credit on slot 1 (alone: L3 and R3 together stay PS5SX2's combos)
	Test,       // the Test switch, on and off (alone, as Coin)
};

struct Control
{
	Src src;
	Act act;
	uint16_t mask = 0;
	uint16_t dir_mask[4] = {}; // Button on a stick or the D-pad: up, down, left, right
	std::string label;         // what it does in this game ("Left Punch", "Gas")
	bool system = false;       // the cabinet's own (Start, coin, Test, Service, Enter, a driving game's menu D-pad)
};

struct GameControls
{
	std::string mode;  // "driving", "fighting", "buttons", "gun", "drum", "touch", "twin levers", "unknown"
	std::vector<Control> rows;
	std::string note;  // what isn't there yet (a cursor, a card reader), or empty
};

// A game's rows, by its gameid (NM00008). Works without the game running.
GameControls ControlsFor(const std::string& gameid);

// The DualSense's name for a control ("Cross", "Left stick").
const char* SrcName(Src s);

// What the controller holds now (main-boot.cpp's OrbisPadData: the buttons' bits, the sticks 0..255, the triggers 0..255).
struct Pad
{
	uint32_t buttons;
	uint8_t lx, ly, rx, ry, l2, r2;
};

// Whether `src` is held in `pad` (a stick: pushed past half way; the triggers: past half way).
bool Held(const Pad& pad, Src src);

// Applies the pad to the JVS board for the running game (ACJV::GetGameId()), and logs its table the first time.
void Apply(const Pad& pad);
} // namespace orbis_arcade
