// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

// PS5SX2x6: an arcade game's boot without the frame limiter (the flag bootturbo; needs proper testing).
//
// Wangan Midnight's boot.log runs at 100% speed from the start to its disc load (about 18 s): the time the game takes on
// the board -- its 1.6 MB loader and every IRX read from the dongle on the memory card port, the i.LINK set-up -- with
// the EE thread waiting in the frame limiter for most of each second. Only running that stretch faster than the board
// shortens it. The boot starts unthrottled (VMBootParameters::start_unlimited) and the limiter comes back at the first of:
//   - the game's first sound: 50 ms of SPU2 output above -40 dB (after the DC filter), counted in spu2Output;
//   - a button newly pressed on player 1's DualSense, from the second second on (the press that started the game is
//     still held at first);
//   - 60 s of game time (the EE's cycles at PS2CLK);
//   - anything else changing the limiter (a hotkey): it is then left alone.
// The emulated time and the wall time at that point go to boot.log: "[bootturbo] off (<why>): <x> s of game time in <y> s".

#include "OrbisBootTurbo.h"

#include "Common.h"
#include "R5900.h"
#include "VMManager.h"

#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdio>

bool g_orbis_bootturbo_listen = false; // EE thread only (spu2Output and the vsync below)

namespace
{
bool s_active = false;
u32 s_loud = 0; // samples above the threshold since the boot started
std::atomic<bool> s_input{false};
std::chrono::steady_clock::time_point s_t0;

constexpr float kLoud = 0.01f; // -40 dBFS
constexpr u32 kLoudSamples = 2400; // 50 ms of 48 kHz frames
constexpr double kMaxGameSeconds = 60.0;

double WallSeconds()
{
	return std::chrono::duration<double>(std::chrono::steady_clock::now() - s_t0).count();
}
} // namespace

void OrbisBootTurboArm()
{
	s_active = true;
	s_loud = 0;
	s_input.store(false, std::memory_order_relaxed);
	s_t0 = std::chrono::steady_clock::now();
	g_orbis_bootturbo_listen = true;
	std::printf("[bootturbo] on: the boot runs without the frame limiter until the game's first sound, a button or %.0f s of game time\n",
		kMaxGameSeconds);
	std::fflush(stdout);
}

void OrbisBootTurboNoteSample(float left, float right)
{
	if (std::fabs(left) > kLoud || std::fabs(right) > kLoud)
		s_loud++;
}

void OrbisBootTurboNoteInput()
{
	if (s_active && WallSeconds() >= 1.0)
		s_input.store(true, std::memory_order_relaxed);
}

void OrbisBootTurboVsync()
{
	if (!s_active)
		return;
	const double game = static_cast<double>(cpuRegs.cycle) / static_cast<double>(PS2CLK);
	const char* why = nullptr;
	if (VMManager::GetLimiterMode() != LimiterModeType::Unlimited)
		why = "the limiter was changed";
	else if (s_loud >= kLoudSamples)
		why = "the game's first sound";
	else if (s_input.load(std::memory_order_relaxed))
		why = "a button";
	else if (game >= kMaxGameSeconds)
		why = "60 s of game time";
	if (!why)
		return;
	s_active = false;
	g_orbis_bootturbo_listen = false;
	if (VMManager::GetLimiterMode() == LimiterModeType::Unlimited)
		VMManager::SetLimiterMode(LimiterModeType::Nominal);
	std::printf("[bootturbo] off (%s): %.1f s of game time in %.1f s\n", why, game, WallSeconds());
	std::fflush(stdout);
}
