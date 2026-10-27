// PS5 port (2026-10-16, AI-assisted): the folders PCSX2's BIOS lookup (pcsx2/ps2/BiosTools.cpp, OrbisFindBiosElsewhere) looks in after
// the BIOS folder's own files. Moved out of it unchanged (vk-285-115, vk-285-118, vk-285-134, 2026-10-08), with two switches:
//
//   only_bios_folder  PS5SX2/BiosFolder is set: the player's folder is the only place, so just the folders inside it (three levels
//                     down, 64 at most) are looked in; not /data/PCSX2, not a bios folder there in another case, not the drives.
//   scan_drives       PS5SX2/ScanUsb is on (the default): each drive (/mnt/usb0-7, /mnt/ext0-1) that holds anything, its bios/,
//                     PS5SX2/ and PCSX2/ folders, and their bios/. Off: no drive is opened.
//
// Header only, so ps5/coreorbis/tests/biosroots/ builds it on a PC (`top` and `mnt` stand in for /data/PCSX2 and /mnt there).
//
// Copyright (C) 2026 swordpdf
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <algorithm>
#include "OrbisDataDir.h"
#include <string>
#include <utility>
#include <vector>

#include <dirent.h>
#include <strings.h>
#include <sys/stat.h>

namespace OrbisBios
{
inline std::vector<std::string> Names(const std::string& dir)
{
	std::vector<std::string> names;
	if (DIR* d = opendir(dir.c_str()))
	{
		while (const dirent* e = readdir(d))
			if (e->d_name[0] != '.' && e->d_name[0] != '$')
				names.emplace_back(e->d_name);
		closedir(d);
	}
	std::sort(names.begin(), names.end());
	return names;
}

inline bool IsDir(const std::string& path)
{
	struct stat st = {};
	return stat(path.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}

// `bios`: EmuFolders::Bios. The folders in it (three levels down, 64 at most) are always looked in, in that order; then, unless
// `only_bios_folder`, /data/PCSX2, its bios folder in another case, and (when `scan_drives`) the drives.
inline std::vector<std::string> SearchDirs(const std::string& bios, bool only_bios_folder, bool scan_drives = true,
	const std::string& top = ORBIS_DATA_DIR, const std::string& mnt = "/mnt")
{
	std::vector<std::string> dirs;
	// vk-285-134 (AI-assisted): the BIOS folder's folders three levels down (64 at most), not one: build 130's logs had
	// BIOS packs unpacked as folders of folders ("ps2 bios usa/", "SCPH-30003_BIOS_V3_UK_120_(PAL)/", ...).
	{
		std::vector<std::pair<std::string, int>> todo = {{bios, 0}};
		for (size_t i = 0; i < todo.size() && dirs.size() < 64; i++)
		{
			const auto [dir, depth] = todo[i];
			if (depth >= 3)
				continue;
			for (const std::string& name : Names(dir))
			{
				if (dirs.size() >= 64)
					break;
				if (IsDir(dir + "/" + name))
				{
					dirs.push_back(dir + "/" + name);
					todo.emplace_back(dir + "/" + name, depth + 1);
				}
			}
		}
	}
	if (only_bios_folder)
		return dirs;
	if (bios != top)
		dirs.push_back(top);
	for (const std::string& name : Names(top))
	{
		if (strcasecmp(name.c_str(), "bios") == 0 && top + "/" + name != bios && IsDir(top + "/" + name))
			dirs.push_back(top + "/" + name);
	}
	if (!scan_drives)
		return dirs;
	// 2026-10-08 (AI-assisted): and the PS5's extended storage / M.2 drives (/mnt/ext0, /mnt/ext1), as the USB drives.
	for (int i = 0; i < 10; i++)
	{
		const std::string root = i < 8 ? mnt + "/usb" + std::to_string(i) : mnt + "/ext" + std::to_string(i - 8);
		const std::vector<std::string> names = Names(root);
		if (names.empty())
			continue;
		dirs.push_back(root);
		for (const std::string& name : names)
		{
			const bool is_bios = strcasecmp(name.c_str(), "bios") == 0;
			// vk-285-118 (AI-assisted): PCSX2/bios too, a drive laid out like /data/PCSX2 (as its games/ and textures/).
			const bool is_ps5sx2 = strcasecmp(name.c_str(), "ps5sx2") == 0 || strcasecmp(name.c_str(), "pcsx2") == 0;
			if (!(is_bios || is_ps5sx2) || !IsDir(root + "/" + name))
				continue;
			dirs.push_back(root + "/" + name);
			if (is_ps5sx2)
			{
				for (const std::string& sub : Names(root + "/" + name))
				{
					if (strcasecmp(sub.c_str(), "bios") == 0 && IsDir(root + "/" + name + "/" + sub))
						dirs.push_back(root + "/" + name + "/" + sub);
				}
			}
		}
	}
	return dirs;
}
} // namespace OrbisBios
