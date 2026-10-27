// PS5SX2x6: this title's data folder and title ID. They differ from PS5SX2's (/data/PCSX2, PPSA99203), so the two
// install side by side: the arcade BIOSes, dongles, settings and logs stay apart from the PS2 ones, and PS5SX2's
// installer, which updates PPSA99203, never touches this title.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#define ORBIS_DATA_DIR "/data/PCSX2x6"
#define ORBIS_TITLE_ID "PPSA97376"

// This title's own eboot: the one "back to the menu", the eboot watcher and the disc payloads start again. Not
// PS5SX2's (/data/homebrew/PPSA99203), which would open PS5SX2's shelf when both are installed.
#define ORBIS_OWN_EBOOT "/data/homebrew/" ORBIS_TITLE_ID "/eboot.bin"
