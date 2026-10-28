// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

// PS5SX2x6: an arcade game's boot without the frame limiter (the flag bootturbo), see OrbisBootTurbo.cpp.

#pragma once

// main-boot.cpp, with the boot parameters' start_unlimited: the boot starts unthrottled.
void OrbisBootTurboArm();

// VMManager::Internal::VSyncOnCPUThread: ends it (the game's first sound, a button, 60 s of game time).
void OrbisBootTurboVsync();

// The pad thread: a button newly pressed on player 1's DualSense.
void OrbisBootTurboNoteInput();

// spu2Output: the samples while the boot is unthrottled (after the DC filter, -1..1).
extern bool g_orbis_bootturbo_listen;
void OrbisBootTurboNoteSample(float left, float right);
