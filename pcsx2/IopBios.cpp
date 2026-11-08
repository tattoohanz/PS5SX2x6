// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "Common.h"
#include "DebugTools/SymbolGuardian.h"
#include "IopBios.h"
#include "IopMem.h"
#include "R3000A.h"
#include "R5900.h"
#include "ps2/BiosTools.h"
#include "VMManager.h"
#include "DEV9/ACJV.h"

#include <ctype.h>
#include <fmt/format.h>
#include <string.h>
#include <sys/stat.h>
#include "common/FileSystem.h"
#include "common/Path.h"

#include <cctype>
#include <cstring>
#include <fmt/format.h>
#include <sys/stat.h>
#include <algorithm>

#include <fcntl.h>

#ifdef _WIN32
#include <io.h>
#include "common/RedtapeWindows.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#if !defined(S_ISREG) && defined(S_IFMT) && defined(S_IFREG)
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#endif
#if !defined(S_ISDIR) && defined(S_IFMT) && defined(S_IFDIR)
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#endif

#ifndef O_BINARY
#define O_BINARY 0
#endif

typedef struct
{
	u32 mode;
	u32 attr;
	u32 size;
	u8 ctime[8];
	u8 atime[8];
	u8 mtime[8];
	u32 hisize;
} fio_stat_t;
typedef struct
{
	fio_stat_t _fioStat;
	/** Number of subs (main) / subpart number (sub) */
	u32 private_0;
	u32 private_1;
	u32 private_2;
	u32 private_3;
	u32 private_4;
	/** Sector start.  */
	u32 private_5;
} fxio_stat_t;

typedef struct
{
	fio_stat_t stat;
	char name[256];
	u32 unknown;
} fio_dirent_t;

typedef struct
{
	fxio_stat_t stat;
	char name[256];
	u32 unknown;
} fxio_dirent_t;

static std::string hostRoot;

void Hle_SetHostRoot(const char* bootFilename)
{
	std::string path = Path::RealPath(bootFilename);
	hostRoot = Path::ToNativePath(Path::GetDirectory(path));
	Console.WriteLn("HLE Host: Set 'host:' root path to: %s", hostRoot.c_str());
}

void Hle_ClearHostRoot()
{
	hostRoot = {};
}

namespace R3000A
{

#define v0 (psxRegs.GPR.n.v0)
#define a0 (psxRegs.GPR.n.a0)
#define a1 (psxRegs.GPR.n.a1)
#define a2 (psxRegs.GPR.n.a2)
#define a3 (psxRegs.GPR.n.a3)
#define sp (psxRegs.GPR.n.sp)
#define ra (psxRegs.GPR.n.ra)
#define pc (psxRegs.pc)

#define Ra0 (iopMemReadString(a0))
#define Ra1 (iopMemReadString(a1))
#define Ra2 (iopMemReadString(a2))
#define Ra3 (iopMemReadString(a3))

	// Stat values differ between iomanX and ioman
	// These values have been taken from the PS2SDK
	// Specifically iox_stat.h
	struct fio_stat_flags
	{
		// Access flags
		// Execute
		int IXOTH;
		// Write
		int IWOTH;
		// Read
		int IROTH;

		// File mode flags
		// Symlink
		int IFLNK;
		// Regular file
		int IFREG;
		// Directory
		int IFDIR;
	};

	fio_stat_flags ioman_stat{
		0x01,
		0x02,
		0x04,
		0x08,
		0x10,
		0x20,
	};

	fio_stat_flags iomanx_stat{
		0x01,
		0x02,
		0x04,
		0x4000,
		0x2000,
		0x1000,
	};

	// This is a workaround for GHS on *NIX platforms
	// Whenever a program splits directories with a backslash (ulaunchelf)
	// the directory is considered non-existant
	static __fi std::string clean_path(const std::string& path)
	{
#ifndef _WIN32
		std::string ret = path;
		std::replace(ret.begin(), ret.end(), '\\', '/');
		return ret;
#else // This function will cause problems with Windows WSL / device paths where forward slashes are required
		return path;
#endif
	}

	static int host_stat(const std::string& path, fio_stat_t* host_stats, fio_stat_flags& stat = ioman_stat)
	{
		struct stat file_stats;
		const std::string file_path(ioman::host_path(path, true));

		if (!FileSystem::StatFile(file_path.c_str(), &file_stats))
			return -IOP_ENOENT;

		host_stats->size = (u32)file_stats.st_size;
		host_stats->hisize = 0;

		// Convert the mode.
		host_stats->mode = (file_stats.st_mode & (stat.IROTH | stat.IWOTH | stat.IXOTH));
#ifndef _WIN32
		if (S_ISLNK(file_stats.st_mode))
		{
			host_stats->mode |= stat.IFLNK;
		}
#endif
		if (S_ISREG(file_stats.st_mode))
		{
			host_stats->mode |= stat.IFREG;
		}
		if (S_ISDIR(file_stats.st_mode))
		{
			host_stats->mode |= stat.IFDIR;
		}

		// Convert the creation time.
		struct tm* loctime;
		loctime = localtime(&(file_stats.st_ctime));
		host_stats->ctime[6] = (unsigned char)loctime->tm_year;
		host_stats->ctime[5] = (unsigned char)loctime->tm_mon + 1;
		host_stats->ctime[4] = (unsigned char)loctime->tm_mday;
		host_stats->ctime[3] = (unsigned char)loctime->tm_hour;
		host_stats->ctime[2] = (unsigned char)loctime->tm_min;
		host_stats->ctime[1] = (unsigned char)loctime->tm_sec;

		// Convert the access time.
		loctime = localtime(&(file_stats.st_atime));
		host_stats->atime[6] = (unsigned char)loctime->tm_year;
		host_stats->atime[5] = (unsigned char)loctime->tm_mon + 1;
		host_stats->atime[4] = (unsigned char)loctime->tm_mday;
		host_stats->atime[3] = (unsigned char)loctime->tm_hour;
		host_stats->atime[2] = (unsigned char)loctime->tm_min;
		host_stats->atime[1] = (unsigned char)loctime->tm_sec;

		// Convert the last modified time.
		loctime = localtime(&(file_stats.st_mtime));
		host_stats->mtime[6] = (unsigned char)loctime->tm_year;
		host_stats->mtime[5] = (unsigned char)loctime->tm_mon + 1;
		host_stats->mtime[4] = (unsigned char)loctime->tm_mday;
		host_stats->mtime[3] = (unsigned char)loctime->tm_hour;
		host_stats->mtime[2] = (unsigned char)loctime->tm_min;
		host_stats->mtime[1] = (unsigned char)loctime->tm_sec;

		return 0;
	}

	static int host_stat(const std::string& path, fxio_stat_t* host_stats)
	{
		return host_stat(path, &host_stats->_fioStat, iomanx_stat);
	}

	// TODO: sandbox option, other permissions
	class HostFile : public IOManFile
	{
	public:
		int fd;

		HostFile(int hostfd)
		{
			fd = hostfd;
		}

		virtual ~HostFile() = default;

		static __fi int translate_error(int err)
		{
			if (err >= 0)
				return err;

			switch (err)
			{
				case -ENOENT:
					return -IOP_ENOENT;
				case -EACCES:
					return -IOP_EACCES;
				case -EISDIR:
					return -IOP_EISDIR;
				case -EIO:
				default:
					return -IOP_EIO;
			}
		}

		static int open(IOManFile** file, const std::string& full_path, s32 flags, u16 mode)
		{
			const std::string path(full_path.substr(full_path.find(':') + 1));
			const std::string file_path(ioman::host_path(path, false));
			int native_flags = O_BINARY; // necessary in Windows.

			switch (flags & IOP_O_RDWR)
			{
				case IOP_O_RDONLY:
					native_flags |= O_RDONLY;
					break;
				case IOP_O_WRONLY:
					native_flags |= O_WRONLY;
					break;
				case IOP_O_RDWR:
					native_flags |= O_RDWR;
					break;
			}

			if (flags & IOP_O_APPEND)
				native_flags |= O_APPEND;
			if (flags & IOP_O_CREAT)
				native_flags |= O_CREAT;
			if (flags & IOP_O_TRUNC)
				native_flags |= O_TRUNC;

#ifdef _WIN32
			const int native_mode = _S_IREAD | _S_IWRITE;
#else
			const int native_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
#endif

			const int hostfd = FileSystem::OpenFDFile(file_path.c_str(), native_flags, native_mode);
			if (hostfd < 0)
				return translate_error(hostfd);

			*file = new HostFile(hostfd);
			if (!*file)
				return -IOP_ENOMEM;

			return 0;
		}

		virtual void close()
		{
			::close(fd);
			delete this;
		}

		virtual int lseek(s32 offset, s32 whence)
		{
			int err;

			switch (whence)
			{
				case IOP_SEEK_SET:
					err = static_cast<int>(::lseek(fd, offset, SEEK_SET));
					break;
				case IOP_SEEK_CUR:
					err = static_cast<int>(::lseek(fd, offset, SEEK_CUR));
					break;
				case IOP_SEEK_END:
					err = static_cast<int>(::lseek(fd, offset, SEEK_END));
					break;
				default:
					return -IOP_EIO;
			}

			return translate_error(err);
		}

		virtual int read(void* buf, u32 count) /* Flawfinder: ignore */
		{
			return translate_error(static_cast<int>(::read(fd, buf, count)));
		}

		virtual int write(void* buf, u32 count)
		{
			return translate_error(static_cast<int>(::write(fd, buf, count)));
		}
	};

	class HostDir : public IOManDir
	{
	public:
		FileSystem::FindResultsArray results;
		FileSystem::FindResultsArray::iterator dir;
		std::string basedir;

		HostDir(FileSystem::FindResultsArray results_, std::string basedir_)
			: results(std::move(results_))
			, basedir(std::move(basedir_))
		{
			dir = results.begin();
		}

		virtual ~HostDir() = default;

		static int open(IOManDir** dir, const std::string& full_path)
		{
			std::string relativePath = full_path.substr(full_path.find(':') + 1);
			std::string path = ioman::host_path(relativePath, true);

			if (!FileSystem::DirectoryExists(path.c_str()))
				return -IOP_ENOENT; // Should return ENOTDIR if path is a file?

			FileSystem::FindResultsArray results;
			FileSystem::FindFiles(path.c_str(), "*", FILESYSTEM_FIND_FILES | FILESYSTEM_FIND_FOLDERS | FILESYSTEM_FIND_RELATIVE_PATHS | FILESYSTEM_FIND_HIDDEN_FILES, &results);

			*dir = new HostDir(std::move(results), std::move(path));
			if (!*dir)
				return -IOP_ENOMEM;

			return 0;
		}

		virtual int read(void* buf, bool iomanX) /* Flawfinder: ignore */
		{
			if (dir == results.end())
				return 0;

			if (iomanX)
			{
				fxio_dirent_t* hostcontent = (fxio_dirent_t*)buf;
				StringUtil::Strlcpy(hostcontent->name, dir->FileName, sizeof(hostcontent->name));
				host_stat(ioman::host_path(Path::Combine(basedir, dir->FileName), true), &hostcontent->stat);
			}
			else
			{
				fio_dirent_t* hostcontent = (fio_dirent_t*)buf;
				StringUtil::Strlcpy(hostcontent->name, dir->FileName, sizeof(hostcontent->name));
				host_stat(ioman::host_path(Path::Combine(basedir, dir->FileName), true), &hostcontent->stat);
			}

			dir = std::next(dir);
			return 1;
		}

		virtual void close()
		{
			delete this;
		}
	};

	struct fileHandle
	{
		u32 fd_index;
		std::string full_path;
		s32 flags;
		u16 mode;
	};

	std::vector<fileHandle> handles;

	namespace ioman
	{
		const int firstfd = 0x100;
		const int maxfds = 0x100;
		int openfds = 0;

		int freefdcount()
		{
			return maxfds - openfds;
		}

		struct filedesc
		{
			enum
			{
				FILE_FREE,
				FILE_FILE,
				FILE_DIR,
			} type;
			union
			{
				IOManFile* file;
				IOManDir* dir;
			};

			constexpr filedesc()
				: type(FILE_FREE)
				, file(nullptr)
			{
			}
			operator bool() const { return type != FILE_FREE; }
			operator IOManFile*() const { return type == FILE_FILE ? file : NULL; }
			operator IOManDir*() const { return type == FILE_DIR ? dir : NULL; }
			void operator=(IOManFile* f)
			{
				type = FILE_FILE;
				file = f;
				openfds++;
			}
			void operator=(IOManDir* d)
			{
				type = FILE_DIR;
				dir = d;
				openfds++;
			}

			void close()
			{
				switch (type)
				{
					case FILE_FILE:
						file->close();
						file = NULL;
						break;
					case FILE_DIR:
						dir->close();
						dir = NULL;
						break;
					case FILE_FREE:
						return;
				}

				type = FILE_FREE;
				openfds--;
			}
		};

		filedesc fds[maxfds];

		template <typename T>
		T* getfd(int fd)
		{
			fd -= firstfd;

			if (fd < 0 || fd >= maxfds)
				return NULL;

			return fds[fd];
		}

		template <typename T>
		int allocfd(T* obj)
		{
			for (int i = 0; i < maxfds; i++)
			{
				if (!fds[i])
				{
					fds[i] = obj;
					return firstfd + i;
				}
			}

			obj->close();
			return -IOP_EMFILE;
		}

		void freefd(int fd)
		{
			fd -= firstfd;

			if (fd < 0 || fd >= maxfds)
				return;

			fds[fd].close();
		}

		void reset()
		{
			for (int i = 0; i < maxfds; i++)
			{
				if (fds[i])
					fds[i].close();
			}
			handles.clear();
		}

		bool is_host(const std::string_view path)
		{
			auto not_number_pos = path.find_first_not_of("0123456789", 4);
			if (not_number_pos == std::string::npos)
				return false;

			return (path.compare(0, 4, "host") == 0 && path[not_number_pos] == ':');
		}

		std::string host_path(const std::string_view path, bool allow_open_host_root)
		{
			// We are NOT allowing to use the root of the host unit.
			// For now it just supports relative folders from the location of the elf
			std::string native_path(Path::Canonicalize(path));
			std::string new_path;
			if (!hostRoot.empty() && native_path.starts_with(hostRoot))
				new_path = std::move(native_path);
			else if (!hostRoot.empty()) // relative paths
				new_path = Path::Combine(hostRoot, native_path);

			// Allow opening the ELF override.
			if (new_path == VMManager::Internal::GetELFOverride())
				return new_path;

			// Allow nothing if hostfs isn't enabled.
			if (!EmuConfig.HostFs)
			{
				new_path.clear();
				return new_path;
			}

			// Double-check that it falls within the directory of the elf.
			// Not a real sandbox, but emulators shouldn't be treated as such. Don't run untrusted code!
			std::string canonicalized_path(Path::Canonicalize(new_path));

			// Are we opening the root of host? (i.e. `host:.` or `host:`)
			// We want to allow this as a directory open, but not as a file open.
			if (!allow_open_host_root || canonicalized_path != hostRoot)
			{
				// Only allow descendants of the hostfs directory.
				if (canonicalized_path.length() <= hostRoot.length() || // Length has to be equal or longer,
					!canonicalized_path.starts_with(hostRoot) || // and start with the host root,
					canonicalized_path[hostRoot.length()] != FS_OSPATH_SEPARATOR_CHARACTER) // and we can't access a sibling.
				{
					Console.Error(fmt::format(
						"IopHLE: Denying access to path outside of ELF directory. Requested path: '{}', Resolved path: '{}', ELF directory: '{}'",
						path, new_path, hostRoot));
					new_path.clear();
				}
			}

			return new_path;
		}

		int open_HLE()
		{
			IOManFile* file = NULL;
			const std::string path = clean_path(Ra0);
			s32 flags = a1;
			u16 mode = a2;

			if (is_host(path))
			{
				if (!freefdcount())
				{
					v0 = -IOP_EMFILE;
					pc = ra;
					return 1;
				}

				int err = HostFile::open(&file, path, flags, mode);

				if (err != 0 || !file)
				{
					if (err == 0) // ???
						err = -IOP_EIO;
					if (file) // ??????
						file->close();
					v0 = err;
				}
				else
				{
					v0 = allocfd(file);
					if ((s32)v0 < 0)
						file->close();
					else
					{
						fileHandle handle;
						handle.fd_index = v0 - firstfd;
						handle.flags = flags;
						handle.full_path = path;
						handle.mode = mode;
						handles.push_back(handle);
					}
				}

				pc = ra;
				return 1;
			}

			return 0;
		}

		int close_HLE()
		{
			s32 fd = a0;

			if (getfd<IOManFile>(fd))
			{
				freefd(fd);

				for (size_t i = 0; i < handles.size(); i++)
				{
					if (handles[i].fd_index == (u32)fd - firstfd)
					{
						handles.erase(handles.begin() + i);
						break;
					}
				}

				v0 = 0;
				pc = ra;
				return 1;
			}

			return 0;
		}

		int dopen_HLE()
		{
			IOManDir* dir = NULL;
			const std::string path = clean_path(Ra0);

			if (is_host(path))
			{
				int err = HostDir::open(&dir, path);

				if (err != 0 || !dir)
				{
					if (err == 0)
						err = -IOP_EIO;
					if (dir)
						dir->close();
					v0 = err;
				}
				else
				{
					v0 = allocfd(dir);
					if ((s32)v0 < 0)
						dir->close();
				}

				pc = ra;
				return 1;
			}

			return 0;
		}

		int dclose_HLE()
		{
			s32 dir = a0;

			if (getfd<IOManDir>(dir))
			{
				freefd(dir);
				v0 = 0;
				pc = ra;
				return 1;
			}

			return 0;
		}

		int _dread_HLE(bool iomanX)
		{
			s32 fh = a0;
			u32 data = a1;
			if (iomanX)
			{
				if (IOManDir* dir = getfd<IOManDir>(fh))
				{
					char buf[sizeof(fxio_dirent_t)];
					v0 = dir->read(&buf, iomanX); /* Flawfinder: ignore */

					for (s32 i = 0; i < (s32)sizeof(fxio_dirent_t); i++)
						iopMemWrite8(data + i, buf[i]);

					pc = ra;
					return 1;
				}
			}
			else
			{
				if (IOManDir* dir = getfd<IOManDir>(fh))
				{
					char buf[sizeof(fio_dirent_t)];
					v0 = dir->read(&buf); /* Flawfinder: ignore */

					for (s32 i = 0; i < (s32)sizeof(fio_dirent_t); i++)
						iopMemWrite8(data + i, buf[i]);

					pc = ra;
					return 1;
				}
			}
			return 0;
		}

		int dread_HLE()
		{
			return _dread_HLE(false);
		}

		int dreadx_HLE()
		{
			return _dread_HLE(true);
		}

		int _getStat_HLE(bool iomanx)
		{
			const std::string path = clean_path(Ra0);
			u32 data = a1;

			if (is_host(path))
			{
				const std::string full_path = host_path(path.substr(path.find(':') + 1), true);
				if (iomanx)
				{
					char buf[sizeof(fxio_stat_t)];
					v0 = host_stat(full_path, (fxio_stat_t*)&buf);

					for (size_t i = 0; i < sizeof(fxio_stat_t); i++)
						iopMemWrite8(static_cast<u32>(data + i), buf[i]);
				}
				else
				{
					char buf[sizeof(fio_stat_t)];
					v0 = host_stat(full_path, (fio_stat_t*)&buf);

					for (size_t i = 0; i < sizeof(fio_stat_t); i++)
						iopMemWrite8(static_cast<u32>(data + i), buf[i]);
				}
				pc = ra;
				return 1;
			}

			return 0;
		}

		int getStat_HLE()
		{
			return _getStat_HLE(false);
		}

		int getStatx_HLE()
		{
			return _getStat_HLE(true);
		}

		int lseek_HLE()
		{
			s32 fd = a0;
			s32 offset = a1;
			s32 whence = a2;

			if (IOManFile* file = getfd<IOManFile>(fd))
			{
				v0 = file->lseek(offset, whence);
				pc = ra;
				return 1;
			}

			return 0;
		}

		int remove_HLE()
		{
			const std::string full_path = clean_path(Ra0);

			if (is_host(full_path))
			{
				const std::string path = full_path.substr(full_path.find(':') + 1);
				const std::string file_path(host_path(path, false));
				const bool succeeded = FileSystem::DeleteFilePath(file_path.c_str());
				if (!succeeded)
					Console.Warning("IOPHLE remove_HLE failed for '%s'", file_path.c_str());
				v0 = succeeded ? 0 : -IOP_EIO;
				pc = ra;
			}
			return 0;
		}

		int mkdir_HLE()
		{
			const std::string full_path = clean_path(Ra0);

			if (is_host(full_path))
			{
				const std::string path = full_path.substr(full_path.find(':') + 1);
				const std::string folder_path(host_path(path, false)); // NOTE: Don't allow creating the ELF directory.
				const bool succeeded = FileSystem::CreateDirectoryPath(folder_path.c_str(), false);
				if (!succeeded)
					Console.Warning("IOPHLE mkdir_HLE failed for '%s'", folder_path.c_str());
				v0 = succeeded ? 0 : -IOP_EIO;
				pc = ra;
				return 1;
			}

			return 0;
		}

		int read_HLE()
		{
			s32 fd = a0;
			u32 data = a1;
			u32 count = a2;

			if (IOManFile* file = getfd<IOManFile>(fd))
			{
				auto buf = std::make_unique<char[]>(count);

				v0 = file->read(buf.get(), count);

				[[likely]]
				if (v0 >= 0 && iopMemSafeWriteBytes(data, buf.get(), v0))
				{
					psxCpu->Clear(data, (v0 + 3) / 4);
				}
				else
				{
					for (s32 i = 0; i < static_cast<s32>(v0); i++)
						iopMemWrite8(data + i, buf[i]);
				}

				pc = ra;
				return 1;
			}

			return 0;
		}

		int rmdir_HLE()
		{
			const std::string full_path = clean_path(Ra0);

			if (is_host(full_path))
			{
				const std::string path = full_path.substr(full_path.find(':') + 1);
				const std::string folder_path(host_path(path, false)); // NOTE: Don't allow removing the elf directory itself.
				const bool succeeded = FileSystem::DeleteDirectory(folder_path.c_str());
				if (!succeeded)
					Console.Warning("IOPHLE rmdir_HLE failed for '%s'", folder_path.c_str());
				v0 = succeeded ? 0 : -IOP_EIO;
				pc = ra;
				return 1;
			}

			return 0;
		}

		int write_HLE()
		{
			s32 fd = a0;
			u32 data = a1;
			u32 count = a2;

			if (fd == 1) // stdout
			{
				const std::string s = Ra1;
				iopConLog(ShiftJIS_ConvertString(s.data(), a2));
				pc = ra;
				v0 = a2;
				return 1;
			}
			else if (IOManFile* file = getfd<IOManFile>(fd))
			{
				auto buf = std::make_unique<char[]>(count);

				[[unlikely]]
				if (!iopMemSafeReadBytes(data, buf.get(), count))
				{
					for (u32 i = 0; i < count; i++)
						buf[i] = iopMemRead8(data + i);
				}

				v0 = file->write(buf.get(), count);

				pc = ra;
				return 1;
			}

			return 0;
		}
	} // namespace ioman

	namespace sysmem
	{
		int Kprintf_HLE()
		{

			// Emulate the expected Kprintf functionality:
			iopMemWrite32(sp, a0);
			iopMemWrite32(sp + 4, a1);
			iopMemWrite32(sp + 8, a2);
			iopMemWrite32(sp + 12, a3);
			pc = ra;

			const std::string fmt = Ra0;

			// From here we're intercepting the Kprintf and piping it to our console, complete with
			// printf-style formatting processing.  This part can be skipped if the user has the
			// console disabled.

			if (!ConsoleLogging.iopConsole.IsActive())
				return 1;

			// maximum allowed size for our buffer before we truncate
			constexpr unsigned int max_len = 4096;
			char tmp[max_len], tmp2[max_len];
			char* ptmp = tmp;
			unsigned int printed_bytes = 0;
			unsigned int n = 1, i = 0, j = 0;

			while (fmt[i] && ptmp < std::end(tmp) - 1)
			{
				const int remaining_buf = static_cast<int>(std::end(tmp) - 1 - ptmp);
				switch (fmt[i])
				{
					case '%':
						j = 0;
						tmp2[j++] = '%';
					_start:
						// let's check whether this is our null terminator
						// before allowing the parser to proceed
						if (fmt[i + 1])
						{
							switch (fmt[++i])
							{
								case '.':
								case 'l':
									if (j >= max_len)
										break;
									tmp2[j++] = fmt[i];
									goto _start;
								default:
									if (fmt[i] >= '0' && fmt[i] <= '9')
									{
										if (j >= max_len)
											break;
										tmp2[j++] = fmt[i];
										goto _start;
									}
									break;
							}
						}

						if (j >= max_len)
							break;
						tmp2[j++] = fmt[i];
						tmp2[j] = 0;

						switch (fmt[i])
						{
							case 'f':
							case 'F':
								printed_bytes = std::min(remaining_buf, snprintf(ptmp, remaining_buf, tmp2, (float)iopMemRead32(sp + n * 4)));
								ptmp += printed_bytes;
								n++;
								break;

							case 'a':
							case 'A':
							case 'e':
							case 'E':
							case 'g':
							case 'G':
								printed_bytes = std::min(remaining_buf, snprintf(ptmp, remaining_buf, tmp2, (double)iopMemRead32(sp + n * 4)));
								ptmp += printed_bytes;
								n++;
								break;

							case 'p':
							case 'i':
							case 'd':
							case 'D':
							case 'o':
							case 'O':
							case 'x':
							case 'X':
							case 'u':
							case 'U':
								printed_bytes = std::min(remaining_buf, snprintf(ptmp, remaining_buf, tmp2, (u32)iopMemRead32(sp + n * 4)));
								ptmp += printed_bytes;
								n++;
								break;

							case 'c':
								printed_bytes = std::min(remaining_buf, snprintf(ptmp, remaining_buf, tmp2, (u8)iopMemRead32(sp + n * 4)));
								ptmp += printed_bytes;
								n++;
								break;

							case 's':
							{
								std::string s = iopMemReadString(iopMemRead32(sp + n * 4));
								printed_bytes = std::min(remaining_buf, snprintf(ptmp, remaining_buf, tmp2, s.data()));
								ptmp += printed_bytes;
								n++;
							}
							break;

							case '%':
								*ptmp++ = fmt[i];
								break;

							default:
								break;
						}
						i++;
						break;

					default:
						*ptmp++ = fmt[i++];
						break;
				}
			}
			pxAssertRel(ptmp >= tmp && ptmp < std::end(tmp), "Overflowed tmp buffer");
			*ptmp = 0;
			iopConLog(ShiftJIS_ConvertString(tmp, 1023));

			return 1;
		}
	} // namespace sysmem

	static u32 s_iopDelayThread;

	namespace loadcore
	{

		u32 GetModList(u32 a0reg)
		{
			/* Loadcore puts a pointer to a static array at 0x3f0 */
			u32 bootmodes_ptr = iopMemRead32(0x3f0);
			/* Search for the main loadcore struct from there */
			u32 lcstring = irxFindLoadcore(bootmodes_ptr);
			u32 lc_struct = 0;

			if (lcstring == 0)
			{
				lc_struct = bootmodes_ptr - 0x20;
			}
			else
			{
				lc_struct = lcstring + 0x18;
			}

			return lc_struct + 0x10;
		}

		// Gets the thread list ptr from thbase
		u32 GetThreadList(u32 a0reg, u32 version)
		{
			// Function 3 returns the main thread manager struct
			u32 function = iopMemRead32(a0reg + 0x20);

			// read the lui
			u32 thstruct = (iopMemRead32(function) & 0xFFFF) << 16;
			thstruct |= iopMemRead32(function + 4) & 0xFFFF;

			u32 list = thstruct + 0x42c;

			if (version > 0x101)
				list = thstruct + 0x430;

			return list;
		}

		void LoadFuncs(u32 a0reg)
		{
			if (!EmuConfig.DebuggerAnalysis.GenerateSymbolsForIRXExports)
				return;

			const std::string modname = iopMemReadString(a0reg + 12, 8);
			s32 version_major = iopMemRead8(a0reg + 9);
			s32 version_minor = iopMemRead8(a0reg + 8);
			DevCon.WriteLn(Color_Gray, "RegisterLibraryEntries: %8.8s version %x.%02x", modname.data(), version_major, version_minor);

			R3000SymbolGuardian.ReadWrite([&](ccc::SymbolDatabase& database) {
				ccc::Result<ccc::SymbolSourceHandle> source = database.get_symbol_source("IRX Export Table");
				if (!source.success())
					return;

				// Enumerate the module symbols that already exist for this IRX
				// module. Really there should only be one.
				std::vector<ccc::ModuleHandle> existing_modules;
				for (const auto& pair : database.modules.handles_from_name(modname))
				{
					const ccc::Module* existing_module = database.modules.symbol_from_handle(pair.second);
					if (!existing_module || !existing_module->is_irx)
						continue;

					// Different major versions, we treat this one as a different module.
					if (existing_module->version_major != version_major)
						continue;

					// RegisterLibraryEntries will fail if the new minor ver is <= the old minor ver
					// and the major version is the same.
					if (existing_module->version_minor >= version_minor)
						return;

					existing_modules.emplace_back(existing_module->handle());
				}

				// Destroy the old symbols for this IRX module if any exist.
				for (ccc::ModuleHandle existing_module : existing_modules)
					database.destroy_symbols_from_module(existing_module, true);

				ccc::Result<ccc::Module*> module_symbol = database.modules.create_symbol(modname, *source, nullptr);
				if (!module_symbol.success())
					return;

				(*module_symbol)->is_irx = true;
				(*module_symbol)->version_major = version_major;
				(*module_symbol)->version_minor = version_minor;

				u32 func = a0reg + 20;
				u32 funcptr = iopMemRead32(func);
				u32 index = 0;
				while (funcptr != 0)
				{
					const char* unqualified_name = irxImportFuncname(modname, index);

					std::string qualified_name;
					if (unqualified_name && unqualified_name[0] != '\0')
						qualified_name = fmt::format("{}[{:02}]::{}", modname, index, unqualified_name);
					else
						qualified_name = fmt::format("{}[{:02}]::unkn_{:02}", modname, index, index);

					ccc::Result<ccc::Function*> function = database.functions.create_symbol(qualified_name, funcptr, *source, *module_symbol);
					if (!function.success())
						return;

					index++;
					func += 4;
					funcptr = iopMemRead32(func);
				}
			});
		}

		void ReleaseFuncs(u32 a0reg)
		{
			const std::string modname = iopMemReadString(a0reg + 12, 8);
			s32 version_major = iopMemRead8(a0reg + 9);
			s32 version_minor = iopMemRead8(a0reg + 8);

			DevCon.WriteLn(Color_Gray, "ReleaseLibraryEntries: %8.8s version %x.%02x", modname.c_str(), version_major, version_minor);

			R3000SymbolGuardian.ReadWrite([&](ccc::SymbolDatabase& database) {
				// Enumerate the module symbols that exist for this IRX module.
				// Really there should only be one.
				std::vector<ccc::ModuleHandle> module_handles;
				for (const auto& pair : database.modules.handles_from_name(modname))
				{
					const ccc::Module* module_symbol = database.modules.symbol_from_handle(pair.second);
					if (!module_symbol || !module_symbol->is_irx)
						continue;

					if (module_symbol->version_major != version_major || module_symbol->version_minor != version_minor)
						continue;

					module_handles.emplace_back(module_symbol->handle());
				}

				// Destroy the symbols for the module.
				for (ccc::ModuleHandle module_handle : module_handles)
					database.destroy_symbols_from_module(module_handle, true);
			});
		}

		int RegisterLibraryEntries_HLE()
		{
			LoadFuncs(a0);

			const std::string modname = iopMemReadString(a0 + 12);
			const u32 version = iopMemRead32(a0 + 8);
			if (modname == "thbase")
			{
				CurrentBiosInformation.iopThreadListAddr = GetThreadList(a0, version);
				// thbase export 33, DelayThread: what the iLINK link's RecvFrom sleeps in while nothing has come.
				s_iopDelayThread = iopMemRead32(a0 + 0x14 + 33 * 4);
			}

			CurrentBiosInformation.iopModListAddr = GetModList(a0);
			return 0;
		}

		int ReleaseLibraryEntries_HLE()
		{
			ReleaseFuncs(a0);
			return 0;
		}
	} // namespace loadcore

	// HLE workaround: suppress the DAEMON module's sec_checker thread on S246/S256 arcade.
	// sec_checker (priority 126) races with mcman for the mcman_io_sema during card detection,
	// causing dongle file opens (mc0:ACCORE etc.) to fail with fd=-6.
	// On real hardware the race doesn't manifest due to different IOP scheduling granularity.
	// This should be revisited if IOP thread scheduling accuracy improves.
	// Toggled via JVS > Extra > "Suppress DAEMON security thread" (ON by default).
	namespace thbase
	{
		static bool s_suppress_next_start = false;

		int CreateThread_HLE()
		{
			u32 priority = iopMemRead32(a0 + 16);
			if (ACJV::IsSuppressDaemonEnabled())
			{
				if (priority >= 126)
				{
					Console.WriteLn("IOP: SUPPRESSING thread (pri=%d >= 126)", priority);
					s_suppress_next_start = true;
				}
			}
			return 0;
		}

		int StartThread_HLE()
		{
			if (s_suppress_next_start)
			{
				s_suppress_next_start = false;
				v0 = 0;
				pc = ra;
				return 1;
			}
			return 0;
		}
	} // namespace thbase

	namespace intrman
	{
		// clang-format off
		static const char* intrname[] = {
			"INT_VBLANK",   "INT_GM",       "INT_CDROM",   "INT_DMA",		//00
			"INT_RTC0",     "INT_RTC1",     "INT_RTC2",    "INT_SIO0",		//04
			"INT_SIO1",     "INT_SPU",      "INT_PIO",     "INT_EVBLANK",	//08
			"INT_DVD",      "INT_PCMCIA",   "INT_RTC3",    "INT_RTC4",		//0C
			"INT_RTC5",     "INT_SIO2",     "INT_HTR0",    "INT_HTR1",		//10
			"INT_HTR2",     "INT_HTR3",     "INT_USB",     "INT_EXTR",		//14
			"INT_FWRE",     "INT_FDMA",     "INT_1A",      "INT_1B",		//18
			"INT_1C",       "INT_1D",       "INT_1E",      "INT_1F",		//1C
			"INT_dmaMDECi", "INT_dmaMDECo", "INT_dmaGPU",  "INT_dmaCD",		//20
			"INT_dmaSPU",   "INT_dmaPIO",   "INT_dmaOTC",  "INT_dmaBERR",	//24
			"INT_dmaSPU2",  "INT_dma8",     "INT_dmaSIF0", "INT_dmaSIF1",	//28
			"INT_dmaSIO2i", "INT_dmaSIO2o", "INT_2E",      "INT_2F",		//2C
			"INT_30",       "INT_31",       "INT_32",      "INT_33",		//30
			"INT_34",       "INT_35",       "INT_36",      "INT_37",		//34
			"INT_38",       "INT_39",       "INT_3A",      "INT_3B",		//38
			"INT_3C",       "INT_3D",       "INT_3E",      "INT_3F",		//3C
			"INT_MAX"														//40
		};
		// clang-format on

		void RegisterIntrHandler_DEBUG()
		{
			if (a0 < std::size(intrname) - 1)
			{
				DevCon.WriteLn(Color_Gray, "RegisterIntrHandler: intr %s, handler %x", intrname[a0], a2);
			}
			else
			{
				DevCon.WriteLn(Color_Gray, "RegisterIntrHandler: intr UNKNOWN (%d), handler %x", a0, a2);
			}
		}
	} // namespace intrman

	// The iLINK socket calls of the System 246 link (Wangan Midnight R's VS), as ILSAMPLE makes them for the EE's
	// sceILsock* RPCs: logged at entry (arguments, data and addresses as hex), and, with <data>/ilink.ini, carried over
	// UDP to one other machine (ilnet below). Without ilink.ini nothing is changed.
	namespace ilsocket
	{
		static u32 s_calls[16];

		static bool ilLogThis(int fn)
		{
			const u32 n = ++s_calls[fn & 15];
			return n <= 200 || (n % 600) == 0;
		}

		static std::string ilHex(u32 addr, u32 len, u32 max = 64)
		{
			std::string out;
			const u32 n = std::min(len, max);
			out.reserve(n * 2 + 4);
			for (u32 i = 0; i < n; i++)
			{
				static const char digits[] = "0123456789abcdef";
				const u8 b = iopMemRead8(addr + i);
				out += digits[b >> 4];
				out += digits[b & 15];
			}
			if (len > max)
				out += "..";
			return out;
		}

		static u32 ilArg(int k) { return iopMemRead32(sp + 0x10 + 4 * (k - 4)); }

		// Buffers the called function fills: dumped at the next iLINK call, after the function has run.
		static u32 s_pendAddr[4], s_pendLen[4];
		static const char* s_pendWhat[4];
		static int s_pendCount;

		static void ilDefer(const char* what, u32 addr, u32 len)
		{
			if (s_pendCount < 4)
			{
				s_pendWhat[s_pendCount] = what;
				s_pendAddr[s_pendCount] = addr;
				s_pendLen[s_pendCount] = len;
				s_pendCount++;
			}
		}

		static void ilFlush()
		{
			for (int i = 0; i < s_pendCount; i++)
				Console.WriteLn("[ilink]   %s at %x after the call: %s", s_pendWhat[i], s_pendAddr[i], ilHex(s_pendAddr[i], s_pendLen[i]).c_str());
			s_pendCount = 0;
		}

		// The whole packet when it differs from the last one of the same kind, leaving out the word at 0x10, which
		// the game counts up in every packet. Up to the last non-zero byte; at most 3000 lines of each kind.
		static u8 s_lastPkt[2][4][0x200];
		static u32 s_lastPktLen[2][4];
		static u32 s_pktChanges[2];

		static void ilPacketChanged(int dir, u32 s, const u8* data, u32 len, u32 call)
		{
			static const char* const kName[2] = {"Send", "Recv"};
			if (s >= 4 || s_pktChanges[dir] >= 3000)
				return;
			const u32 n = std::min<u32>(len, 0x200);
			int firstDiff = (n != s_lastPktLen[dir][s]) ? 0 : -1;
			for (u32 i = 0; i < n && firstDiff < 0; i++)
				if ((i < 0x10 || i >= 0x14) && data[i] != s_lastPkt[dir][s][i])
					firstDiff = static_cast<int>(i);
			std::memcpy(s_lastPkt[dir][s], data, n);
			s_lastPktLen[dir][s] = n;
			if (firstDiff < 0)
				return;
			s_pktChanges[dir]++;
			u32 used = n;
			while (used > 0 && data[used - 1] == 0)
				used--;
			std::string hex;
			hex.reserve(used * 2);
			for (u32 i = 0; i < used; i++)
			{
				char h[3];
				std::snprintf(h, sizeof(h), "%02x", data[i]);
				hex += h;
			}
			Console.WriteLn("[ilink] %s packet changed #%u s=%d (call #%u, first diff at %x, %u bytes, zeros after %x) full=%s",
				kName[dir], s_pktChanges[dir], s, call, firstDiff, n, used, hex.c_str());
		}

		static void ilSendFull(u32 s, u32 addr, u32 len)
		{
			u8 data[0x200];
			const u32 n = std::min<u32>(len, 0x200);
			for (u32 i = 0; i < n; i++)
				data[i] = iopMemRead8(addr + i);
			ilPacketChanged(0, s, data, n, s_calls[12]);
		}

		void Init_DEBUG() { ilFlush(); if (ilLogThis(4)) Console.WriteLn("[ilink] Init (%x, %x)", a0, a1); }
		void Reset_DEBUG() { ilFlush(); if (ilLogThis(5)) Console.WriteLn("[ilink] Reset"); }
		void Open_DEBUG() { ilFlush(); if (ilLogThis(8)) Console.WriteLn("[ilink] Open domain=%d type=%d protocol=%d", a0, a1, a2); }
		void Close_DEBUG() { ilFlush(); if (ilLogThis(9)) Console.WriteLn("[ilink] Close s=%d", a0); }
		void Bind_DEBUG() { ilFlush(); if (ilLogThis(10)) Console.WriteLn("[ilink] Bind s=%d addr=%s (len %d)", a0, ilHex(a1, a2).c_str(), a2); }
		void Connect_DEBUG() { ilFlush(); if (ilLogThis(11)) Console.WriteLn("[ilink] Connect s=%d addr=%s (len %d)", a0, ilHex(a1, a2).c_str(), a2); }
		void Send_DEBUG()
		{
			ilFlush();
			if (ilLogThis(12))
				Console.WriteLn("[ilink] Send #%u s=%d len=%d flags=%x data=%s", s_calls[12], a0, a2, a3, ilHex(a1, a2).c_str());
			ilSendFull(a0, a1, a2);
		}
		void SendTo_DEBUG() { ilFlush(); if (ilLogThis(13)) Console.WriteLn("[ilink] SendTo #%u s=%d len=%d flags=%x to=%s data=%s", s_calls[13], a0, a2, a3, ilHex(ilArg(4), ilArg(5)).c_str(), ilHex(a1, a2).c_str()); }
		static bool ilIsRetry(int fn);

		void Recv_DEBUG()
		{
			if (ilIsRetry(14))
				return;
			ilFlush();
			if (ilLogThis(14))
			{
				Console.WriteLn("[ilink] Recv #%u s=%d buf=%x max=%d flags=%x", s_calls[14], a0, a1, a2, a3);
				ilDefer("Recv data", a1, a2);
			}
		}
		void RecvFrom_DEBUG()
		{
			if (ilIsRetry(15))
				return;
			ilFlush();
			if (ilLogThis(15))
			{
				Console.WriteLn("[ilink] RecvFrom #%u s=%d buf=%x max=%d flags=%x from=%x", s_calls[15], a0, a1, a2, a3, ilArg(4));
				ilDefer("RecvFrom data", a1, a2);
				ilDefer("RecvFrom from", ilArg(4), 16);
			}
		}

		// ---- ilnet: the link over UDP ----
		// <data>/ilink.ini (one "key = value" per line, # comments):
		//   peer = 192.168.1.20   the other machine's IP (required)
		//   port = 24680          UDP port, the same on both machines (default 24680)
		//   node = 1              1 on one machine, 2 on the other (default 1)
		//   guid = 074600086af2ff01   optional: the 8 bytes sce1394 GUID gives, in memory order
		// Datagram: "IL1\0", source GUID (8), destination EUI64 (8), destination port (2), source port (2), data.
		// Ports and EUI64s are the bytes of the game's 16-byte addresses (10 3c <port:2> <eui64:8> 00000000).
		namespace ilnet
		{
#ifdef _WIN32
			using sock_t = SOCKET;
			static constexpr sock_t kNoSock = INVALID_SOCKET;
			static void sockClose(sock_t s) { closesocket(s); }
#else
			using sock_t = int;
			static constexpr sock_t kNoSock = -1;
			static void sockClose(sock_t s) { close(s); }
#endif
			static constexpr u32 kMaxData = 0x200;
			static constexpr int kSockets = 8;

			struct Packet
			{
				u8 srcGuid[8];
				u8 srcPort[2];
				u32 len;
				u8 data[kMaxData];
			};

			struct ILSock
			{
				u8 port[2]; // bound
				u8 peerEui[8]; // connected
				u8 peerPort[2];
				bool connected;
				std::vector<Packet> queue;
			};

			static bool s_loaded, s_enabled;
			static sock_t s_udp = kNoSock;
			static sockaddr_in s_peer;
			static u8 s_guid[8] = {0x07, 0x46, 0x00, 0x08, 0x6a, 0xf2, 0xff, 0x01};
			static int s_node = 1;
			static ILSock s_socks[kSockets];
			static u32 s_rxCount, s_txCount, s_dropCount;

			static std::string trim(std::string v)
			{
				while (!v.empty() && (v.back() == ' ' || v.back() == '\t' || v.back() == '\r' || v.back() == '\n'))
					v.pop_back();
				size_t i = 0;
				while (i < v.size() && (v[i] == ' ' || v[i] == '\t'))
					i++;
				return v.substr(i);
			}

			static void load()
			{
				if (s_loaded)
					return;
				s_loaded = true;
				const std::string path = Path::Combine(EmuFolders::DataRoot, "ilink.ini");
				std::FILE* f = std::fopen(path.c_str(), "r");
				if (!f)
				{
					Console.WriteLn("[ilnet] no %s: the link stays as it is (log only)", path.c_str());
					return;
				}
				std::string peer;
				int port = 24680;
				bool guidSet = false;
				char line[256];
				while (std::fgets(line, sizeof(line), f))
				{
					std::string l = line;
					const size_t hash = l.find('#');
					if (hash != std::string::npos)
						l.resize(hash);
					const size_t eq = l.find('=');
					if (eq == std::string::npos)
						continue;
					const std::string key = trim(l.substr(0, eq));
					const std::string val = trim(l.substr(eq + 1));
					if (key == "peer")
						peer = val;
					else if (key == "port")
						port = std::atoi(val.c_str());
					else if (key == "node")
						s_node = std::atoi(val.c_str());
					else if (key == "guid" && val.size() == 16)
					{
						for (int i = 0; i < 8; i++)
							s_guid[i] = static_cast<u8>(std::strtoul(val.substr(i * 2, 2).c_str(), nullptr, 16));
						guidSet = true;
					}
				}
				std::fclose(f);
				if (s_node < 1 || s_node > 63)
					s_node = 1;
				if (!guidSet)
					s_guid[7] = static_cast<u8>(s_node);

				s_peer = {};
				s_peer.sin_family = AF_INET;
				s_peer.sin_port = htons(static_cast<u16>(port));
				if (peer.empty() || inet_pton(AF_INET, peer.c_str(), &s_peer.sin_addr) != 1)
				{
					Console.Error("[ilnet] %s: no valid \"peer = <IP>\", the link stays as it is", path.c_str());
					return;
				}

#ifdef _WIN32
				WSADATA wsa;
				if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
				{
					Console.Error("[ilnet] WSAStartup failed, the link stays as it is");
					return;
				}
#endif
				s_udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
				if (s_udp == kNoSock)
				{
					Console.Error("[ilnet] socket() failed (%d), the link stays as it is", errno);
					return;
				}
				int one = 1;
				setsockopt(s_udp, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&one), sizeof(one));
				sockaddr_in local = {};
				local.sin_family = AF_INET;
				local.sin_addr.s_addr = htonl(INADDR_ANY);
				local.sin_port = htons(static_cast<u16>(port));
				if (bind(s_udp, reinterpret_cast<const sockaddr*>(&local), sizeof(local)) != 0)
				{
					Console.Error("[ilnet] bind to UDP port %d failed (%d), the link stays as it is", port, errno);
					sockClose(s_udp);
					s_udp = kNoSock;
					return;
				}
#ifdef _WIN32
				u_long nb = 1;
				ioctlsocket(s_udp, FIONBIO, &nb);
#else
				fcntl(s_udp, F_SETFL, fcntl(s_udp, F_GETFL, 0) | O_NONBLOCK);
#endif
				s_enabled = true;
				Console.WriteLn("[ilnet] on: UDP port %d, peer %s:%d, node %d, GUID %02x%02x%02x%02x%02x%02x%02x%02x, NodeId %x, DelayThread %x",
					port, peer.c_str(), port, s_node, s_guid[0], s_guid[1], s_guid[2], s_guid[3], s_guid[4], s_guid[5], s_guid[6],
					s_guid[7], 0xffc0 | (s_node - 1), s_iopDelayThread);
			}

			static bool eq2(const u8* a, const u8* b) { return a[0] == b[0] && a[1] == b[1]; }

			// Everything waiting on the UDP socket, into the queues of the sockets bound to its destination port.
			// Into the queue of the socket bound to the destination port.
			static bool enqueue(const u8* srcGuid, const u8* srcPort, const u8* dstPort, const u8* data, u32 len)
			{
				if (dstPort[0] == 0 && dstPort[1] == 0)
					return false;
				for (ILSock& k : s_socks)
				{
					if (!eq2(k.port, dstPort))
						continue;
					if (k.queue.size() >= 64)
						k.queue.erase(k.queue.begin());
					Packet p;
					std::memcpy(p.srcGuid, srcGuid, 8);
					std::memcpy(p.srcPort, srcPort, 2);
					p.len = std::min(len, kMaxData);
					std::memcpy(p.data, data, p.len);
					k.queue.push_back(p);
					return true;
				}
				return false;
			}

			static void poll()
			{
				u8 dg[24 + kMaxData];
				for (;;)
				{
					sockaddr_in from = {};
					socklen_t fromLen = sizeof(from);
					const int n = static_cast<int>(recvfrom(s_udp, reinterpret_cast<char*>(dg), sizeof(dg), 0,
						reinterpret_cast<sockaddr*>(&from), &fromLen));
					if (n < 0)
						return;
					if (n < 24 || std::memcmp(dg, "IL1", 4) != 0 || std::memcmp(dg + 4, s_guid, 8) == 0)
					{
						s_dropCount++;
						continue;
					}
					const u8* dstEui = dg + 12;
					const u8* dstPort = dg + 20;
					bool forMe = true;
					for (int i = 0; i < 8; i++)
						forMe = forMe && (dstEui[i] == 0xff || dstEui[i] == s_guid[i]);
					const bool queued = enqueue(dg + 4, dg + 22, dstPort, dg + 24, static_cast<u32>(n - 24));
					s_rxCount++;
					if (s_rxCount <= 20 || (s_rxCount % 600) == 0)
					{
						char ip[INET_ADDRSTRLEN] = "?";
						inet_ntop(AF_INET, &from.sin_addr, ip, sizeof(ip));
						Console.WriteLn("[ilnet] rx #%u %u bytes from %s to port %02x%02x eui %s%s", s_rxCount, n - 24, ip,
							dstPort[0], dstPort[1], forMe ? "ok" : "other", queued ? "" : " (no socket on that port, dropped)");
					}
				}
			}

			static void send(u32 s, const u8* dstEui, const u8* dstPort, u32 buf, u32 len)
			{
				u8 dg[24 + kMaxData];
				len = std::min(len, kMaxData);
				std::memcpy(dg, "IL1", 4);
				std::memcpy(dg + 4, s_guid, 8);
				std::memcpy(dg + 12, dstEui, 8);
				std::memcpy(dg + 20, dstPort, 2);
				std::memcpy(dg + 22, s_socks[s].port, 2);
				for (u32 i = 0; i < len; i++)
					dg[24 + i] = iopMemRead8(buf + i);
				const int r = static_cast<int>(sendto(s_udp, reinterpret_cast<const char*>(dg), 24 + len, 0,
					reinterpret_cast<const sockaddr*>(&s_peer), sizeof(s_peer)));
				// A broadcast reaches the sender's own sockets too, as on the bus: the game counts on it. In the VS
				// handshake (AL3LOAD 0x1b7fc0) the accepting side broadcasts the ack (word 1 = 4) and then waits for
				// an ack itself (state bit 0x10, set at 0x1b8330) for 181 frames; without its own copy it gives up.
				// Its own hellos it skips by GUID (0x1b83xx) or by their "connected" bit.
				bool broadcast = true;
				for (int i = 0; i < 8; i++)
					broadcast = broadcast && dstEui[i] == 0xff;
				if (broadcast)
					enqueue(s_guid, s_socks[s].port, dstPort, dg + 24, len);
				s_txCount++;
				if (s_txCount <= 5 || (s_txCount % 600) == 0 || r < 0)
					Console.WriteLn("[ilnet] tx #%u s=%u %u bytes to port %02x%02x -> %d", s_txCount, s, len, dstPort[0], dstPort[1], r);
			}

			// A Recv/RecvFrom with nothing to give: the calling thread sleeps 1 ms in thbase's DelayThread, which
			// returns to the jal of the import stub, so the call is made again with the arguments saved here.
			struct Pending
			{
				bool active;
				u32 retAddr;
				u32 args[6];
			};
			static Pending s_pend[16];

			static bool takeArgs(int fn, u32* args, int count)
			{
				Pending& p = s_pend[fn];
				if (p.active && p.retAddr == ra)
				{
					std::memcpy(args, p.args, sizeof(u32) * count);
					return true;
				}
				p.active = false;
				args[0] = a0;
				args[1] = a1;
				args[2] = a2;
				args[3] = a3;
				if (count > 4)
					args[4] = ilArg(4);
				if (count > 5)
					args[5] = ilArg(5);
				return false;
			}

			static int sleepAndRetry(int fn, const u32* args, int count)
			{
				if (!s_iopDelayThread)
				{
					// No DelayThread known: say "nothing" (0 bytes) rather than spin.
					s_pend[fn].active = false;
					v0 = 0;
					pc = ra;
					return 1;
				}
				Pending& p = s_pend[fn];
				p.active = true;
				p.retAddr = ra;
				std::memcpy(p.args, args, sizeof(u32) * count);
				ra = ra - 8; // the jal into the import stub
				a0 = 1000;
				pc = s_iopDelayThread;
				return 1;
			}
		} // namespace ilnet

		static bool ilIsRetry(int fn) { return ilnet::s_pend[fn].active && ilnet::s_pend[fn].retAddr == ra; }

		int Init_HLE()
		{
			ilnet::load();
			if (ilnet::s_enabled)
			{
				for (ilnet::ILSock& k : ilnet::s_socks)
					k = {};
				for (ilnet::Pending& p : ilnet::s_pend)
					p = {};
			}
			return 0; // ILSOCK's own Init runs too
		}

		int Bind_HLE()
		{
			ilnet::load();
			if (ilnet::s_enabled && a0 < ilnet::kSockets && a2 >= 4)
			{
				ilnet::s_socks[a0].port[0] = iopMemRead8(a1 + 2);
				ilnet::s_socks[a0].port[1] = iopMemRead8(a1 + 3);
			}
			return 0; // and ILSOCK's Bind
		}

		int Connect_HLE()
		{
			ilnet::load();
			if (ilnet::s_enabled && a0 < ilnet::kSockets && a2 >= 12)
			{
				ilnet::ILSock& k = ilnet::s_socks[a0];
				k.peerPort[0] = iopMemRead8(a1 + 2);
				k.peerPort[1] = iopMemRead8(a1 + 3);
				for (int i = 0; i < 8; i++)
					k.peerEui[i] = iopMemRead8(a1 + 4 + i);
				k.connected = true;
				// Not ILSOCK's Connect: with no node of that EUI64 on its bus, it fails, and the game takes the
				// peer it heard as gone (AL3LOAD 0x1b84a0: on an error it goes back to listening for hellos).
				v0 = 0;
				pc = ra;
				return 1;
			}
			return 0;
		}

		int Send_HLE()
		{
			if (!ilnet::s_enabled || a0 >= ilnet::kSockets)
				return 0;
			ilnet::ILSock& k = ilnet::s_socks[a0];
			if (!k.connected)
				return 0;
			ilnet::send(a0, k.peerEui, k.peerPort, a1, a2);
			v0 = a2;
			pc = ra;
			return 1;
		}

		int SendTo_HLE()
		{
			if (!ilnet::s_enabled || a0 >= ilnet::kSockets)
				return 0;
			const u32 to = ilArg(4);
			u8 eui[8], port[2];
			port[0] = iopMemRead8(to + 2);
			port[1] = iopMemRead8(to + 3);
			for (int i = 0; i < 8; i++)
				eui[i] = iopMemRead8(to + 4 + i);
			ilnet::send(a0, eui, port, a1, a2);
			v0 = a2;
			pc = ra;
			return 1;
		}

		static int ilReceive(int fn, bool withFrom)
		{
			if (!ilnet::s_enabled)
				return 0;
			u32 args[6];
			ilnet::takeArgs(fn, args, withFrom ? 6 : 4);
			const u32 s = args[0], buf = args[1], max = args[2];
			if (s >= ilnet::kSockets)
				return 0;
			ilnet::poll();
			ilnet::ILSock& k = ilnet::s_socks[s];
			if (k.queue.empty())
				return ilnet::sleepAndRetry(fn, args, withFrom ? 6 : 4);

			ilnet::s_pend[fn].active = false;
			const ilnet::Packet p = k.queue.front();
			k.queue.erase(k.queue.begin());
			const u32 n = std::min(p.len, max);
			for (u32 i = 0; i < n; i++)
				iopMemWrite8(buf + i, p.data[i]);
			ilPacketChanged(1, s, p.data, n, s_calls[fn]);
			if (withFrom && args[4])
			{
				const u32 from = args[4];
				const u8 addr[16] = {0x10, 0x3c, p.srcPort[0], p.srcPort[1], p.srcGuid[0], p.srcGuid[1], p.srcGuid[2],
					p.srcGuid[3], p.srcGuid[4], p.srcGuid[5], p.srcGuid[6], p.srcGuid[7], 0, 0, 0, 0};
				for (int i = 0; i < 16; i++)
					iopMemWrite8(from + i, addr[i]);
				if (args[5])
					iopMemWrite32(args[5], 16);
			}
			v0 = n;
			pc = ra;
			return 1;
		}

		int Recv_HLE() { return ilReceive(14, false); }
		int RecvFrom_HLE() { return ilReceive(15, true); }
	} // namespace ilsocket

	namespace ilink
	{
		int Eui64_HLE()
		{
			ilsocket::ilnet::load();
			if (!ilsocket::ilnet::s_enabled || !a0)
				return 0;
			for (int i = 0; i < 8; i++)
				iopMemWrite8(a0 + i, ilsocket::ilnet::s_guid[i]);
			v0 = 0;
			pc = ra;
			return 1;
		}

		int NodeId_HLE()
		{
			ilsocket::ilnet::load();
			if (!ilsocket::ilnet::s_enabled)
				return 0;
			v0 = 0xffc0 | (ilsocket::ilnet::s_node - 1);
			pc = ra;
			return 1;
		}

		void Eui64_DEBUG()
		{
			ilsocket::ilFlush();
			Console.WriteLn("[ilink] sce1394 #27 (GUID) buf=%x", a0);
			ilsocket::ilDefer("GUID", a0, 8);
		}
		void NodeId_DEBUG() { ilsocket::ilFlush(); Console.WriteLn("[ilink] sce1394 #28 (NodeId)"); }
	} // namespace ilink

	namespace sifcmd
	{
		std::map<u32,std::string> rpcservice_map = {
			// SYSTEM2x6 std IRX
			{0x76500003,	"ACJV"},
			{0x76500001,	"ACMEME"},
			{0x76500002,	"ACCDVDE"},
			{0xFFFF,		"ACRTC"},
			// system2x6 game specific
			{0x6502,		"UARTMAN (IDOLM@STER card reader)"},
			{0x76500004,	"ACNSWE (RRV Force feedback motor)"},
			{0x1000,		"SSM (Bloody Roar 3 audio core)"},
			
			// sony std IRX
			{0x80000001,	"FILEIO"},
			{0x80000003,	"FILEIO (Heap alloc)"},
			{0x80000006,	"LOADFILE"},
			{0x80000100,	"PADMAN"},
			{0x80000101,	"PADMAN (extension)"},
			{0x80000400,	"MCSERV"},
			{0x80000592,	"CDVDFSV (init)"},
			{0x80000593,	"CDVDFSV (CDVD S commands)"},
			{0x80000595,	"CDVDFSV (CDVD N commands)"},
			{0x80000597,	"CDVDFSV (CDVD SearchFile)"},
			{0x8000059A,	"CDVDFSV (CDVD Disk Ready)"},
			{0x80000701,	"SDRDRV"},
			{0x80000901,	"MTAPMAN Port Open"},
			{0x80000902,	"MTAPMAN Port Close"},
			{0x80000903,	"MTAPMAN Get Connection"},
			{0x80000904,	"MTAPMAN"},
			{0x80000905,	"MTAPMAN"},
			{0x80001400,	"EYETOY"},
		};
		void sceSifRegisterRpc_DEBUG()
		{

    		auto it = rpcservice_map.find(a1);
    		if (it != rpcservice_map.end())
    		    DevCon.WriteLn(Color_Gray, "IOP: sceSifRegisterRpc server_id=%08X alias:'%s'", a1, it->second.c_str());
    		else
        		DevCon.WriteLn(Color_Gray, "IOP: sceSifRegisterRpc server_id=%08X (unknown)", a1);
		}
	} // namespace sifcmd

	u32 irxFindLoadcore(u32 entrypc)
	{
		u32 i;

		i = entrypc;
		while (entrypc - i < 0x50)
		{
			// find loadcore string
			if (iopMemRead32(i) == 0x49497350 && iopMemRead32(i + 4) == 0x64616F6C)
			{
				return i;
			}
			i -= 4;
		}

		return 0;
	}

	u32 irxImportTableAddr(u32 entrypc)
	{
		u32 i;

		i = entrypc - 0x18;
		while (entrypc - i < 0x2000)
		{
			if (iopMemRead32(i) == 0x41e00000)
				return i;
			i -= 4;
		}

		return 0;
	}

	const char* irxImportFuncname(const std::string& libname, u16 index)
	{
#include "IopModuleNames.cpp"

		switch (index)
		{
			case 0:
				return "start";
			// case 1: reinit?
			case 2:
				return "shutdown";
				// case 3: ???
		}

		return "";
	}

	// clang-format off
#define MODULE(n)          \
	if (#n == libname)     \
	{                      \
		using namespace n; \
		switch (index)     \
		{
#define END_MODULE \
	}              \
	}
#define EXPORT_D(i, n) \
	case (i):          \
		return n##_DEBUG;
#define EXPORT_H(i, n) \
	case (i):          \
		return n##_HLE;
	// clang-format on

	irxHLE irxImportHLE(const std::string& libname, u16 index)
	{
		// debugging output
		// clang-format off
		MODULE(loadcore)
			EXPORT_H(  6, RegisterLibraryEntries)
			EXPORT_H(  7, ReleaseLibraryEntries);
		END_MODULE
		MODULE(sysmem)
			EXPORT_H( 14, Kprintf)
		END_MODULE
		MODULE(thbase)
			EXPORT_H(  4, CreateThread)
			EXPORT_H(  6, StartThread)
		END_MODULE
		MODULE(ilsocket)
			EXPORT_H(  4, Init)
			EXPORT_H( 10, Bind)
			EXPORT_H( 11, Connect)
			EXPORT_H( 12, Send)
			EXPORT_H( 13, SendTo)
			EXPORT_H( 14, Recv)
			EXPORT_H( 15, RecvFrom)
		END_MODULE
		MODULE(ilink)
			EXPORT_H( 27, Eui64)
			EXPORT_H( 28, NodeId)
		END_MODULE

		// Special case with ioman and iomanX
		// They are mostly compatible excluding stat structures
		if(libname == "ioman" || libname == "iomanx")
		{
			const bool use_ioman = libname == "ioman";
			using namespace ioman;
				switch(index)
				{
					EXPORT_H(  4, open)
					EXPORT_H(  5, close)
					EXPORT_H(  6, read)
					EXPORT_H(  7, write)
					EXPORT_H(  8, lseek)
					EXPORT_H( 10, remove)
					EXPORT_H( 11, mkdir)
					EXPORT_H( 12, rmdir)
					EXPORT_H( 13, dopen)
					EXPORT_H( 14, dclose)
					case 15: // dread
					if(use_ioman)
						return dread_HLE;
					else
						return dreadx_HLE;
					case 16: // getStat
					if(use_ioman)
						return getStat_HLE;
					else
						return getStatx_HLE;
				}
		}
		// clang-format on
		return 0;
	}

	irxDEBUG irxImportDebug(const std::string& libname, u16 index)
	{
		// clang-format off
		MODULE(intrman)
			EXPORT_D(  4, RegisterIntrHandler)
		END_MODULE
		MODULE(sifcmd)
			EXPORT_D( 17, sceSifRegisterRpc)
		END_MODULE
		MODULE(ilsocket)
			EXPORT_D(  4, Init)
			EXPORT_D(  5, Reset)
			EXPORT_D(  8, Open)
			EXPORT_D(  9, Close)
			EXPORT_D( 10, Bind)
			EXPORT_D( 11, Connect)
			EXPORT_D( 12, Send)
			EXPORT_D( 13, SendTo)
			EXPORT_D( 14, Recv)
			EXPORT_D( 15, RecvFrom)
		END_MODULE
		MODULE(ilink)
			EXPORT_D( 27, Eui64)
			EXPORT_D( 28, NodeId)
		END_MODULE
		// clang-format off

		return 0;
	}

#undef MODULE
#undef END_MODULE
#undef EXPORT_D
#undef EXPORT_H

	void irxImportLog(const std::string& libname, u16 index, const char* funcname)
	{
		PSXBIOS_LOG("%8.8s.%03d: %s (%x, %x, %x, %x)",
			libname.data(), index, funcname ? funcname : "unknown",
			a0, a1, a2, a3);
	}

	void irxImportLog_rec(u32 import_table, u16 index, const char* funcname)
	{
		irxImportLog(iopMemReadString(import_table + 12, 8), index, funcname);
	}

	int irxImportExec(u32 import_table, u16 index)
	{
		if (!import_table)
			return 0;

		std::string libname = iopMemReadString(import_table + 12, 8);
		const char* funcname = irxImportFuncname(libname, index);
		irxHLE hle = irxImportHLE(libname, index);
		irxDEBUG debug = irxImportDebug(libname, index);

		irxImportLog(libname, index, funcname);

		if (debug)
			debug();

		if (hle)
			return hle();
		else
			return 0;
	}

} // end namespace R3000A

bool SaveStateBase::handleFreeze()
{
	if (!FreezeTag("hostHandles"))
		return false;

	if (EmuConfig.HostFs && IsLoading())
		R3000A::ioman::reset();

	const int firstfd = R3000A::ioman::firstfd;
	size_t handleCount = EmuConfig.HostFs ? R3000A::handles.size() : 0;
	Freeze(handleCount);

	if (!EmuConfig.HostFs) //if hostfs isn't enabled, skip loading/saving file handles
		return IsOkay();

	for (size_t i = 0; i < handleCount; i++)
	{
		if (IsLoading())
		{
			//load the parameters for opening the file
			s32 pos;
			Freeze(pos);

			R3000A::fileHandle handle;
			Freeze(handle.flags);
			FreezeString(handle.full_path);
			Freeze(handle.mode);
			R3000A::handles.push_back(handle);

			//reopen the file
			IOManFile* file = NULL;
			R3000A::HostFile::open(&file, handle.full_path, handle.flags, handle.mode);
			if (!file)
			{
				Console.Warning("Failed to open file: '%s'", handle.full_path.c_str());
				continue;
			}
			R3000A::handles[i].fd_index = R3000A::ioman::allocfd(file) - firstfd;

			//seek file to position when saved
			file->lseek(pos, SEEK_SET);
		}
		else
		{
			//save the current file position
			const u32 fd = R3000A::handles[i].fd_index;
			IOManFile* file = R3000A::ioman::getfd<IOManFile>(fd + firstfd);
			s32 pos = file ? file->lseek(0, SEEK_CUR) : 0;
			Freeze(pos);

			//save the parameters for opening the file
			Freeze(R3000A::handles[i].flags);
			FreezeString(R3000A::handles[i].full_path);
			Freeze(R3000A::handles[i].mode);
		}
	}
	return IsOkay();
}
