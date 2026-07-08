using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Il2CppInterop.Runtime.Injection
{
    /* Slop code to work in place of xdl to reduce the need for a native dependency */
    internal static class ElfSymbolHelpers
    {
        private const uint SHT_SYMTAB = 2;
        private const uint SHT_DYNSYM = 11;

        public struct MappedModule
        {
            public string Path;
            public ulong BaseAddress;
        }

        public static MappedModule? FindModule(string moduleName)
        {
            foreach (var line in File.ReadLines("/proc/self/maps"))
            {
                // format: base-end perms offset dev inode path
                if (!line.EndsWith(moduleName, StringComparison.Ordinal) &&
                    !line.Contains(moduleName + " ") && !line.Contains(moduleName))
                    continue;

                var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 6) continue;

                var path = parts[5];
                if (!path.EndsWith(moduleName)) continue;

                var addrRange = parts[0].Split('-');
                var baseAddr = Convert.ToUInt64(addrRange[0], 16);

                return new MappedModule { Path = path, BaseAddress = baseAddr };
            }
            return null;
        }

        public static ulong? FindLoadBias(string moduleName, out string? resolvedPath)
        {
            resolvedPath = null;

            foreach (var line in File.ReadLines("/proc/self/maps"))
            {
                var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 6) continue;

                var path = parts[^1];
                if (!path.EndsWith(moduleName, StringComparison.Ordinal)) continue;

                var offset = Convert.ToUInt64(parts[2], 16);
                if (offset != 0) continue; // we want the segment mapping file offset 0

                var addrRange = parts[0].Split('-');
                resolvedPath = path;
                return Convert.ToUInt64(addrRange[0], 16);
            }
            return null;
        }

        public static IntPtr ResolveFileRelativeSymbol(string soPath, string symbolName)
        {
            using var fs = new FileStream(soPath, FileMode.Open, FileAccess.Read);
            using var br = new BinaryReader(fs);

            // --- ELF header ---
            var magic = br.ReadBytes(4);
            if (magic[0] != 0x7F || magic[1] != 'E' || magic[2] != 'L' || magic[3] != 'F')
                throw new InvalidDataException("Not an ELF file");

            byte eiClass = br.ReadByte(); // 1 = 32-bit, 2 = 64-bit
            if (eiClass != 2)
                throw new NotSupportedException("Only ELF64 supported");

            fs.Seek(0x28, SeekOrigin.Begin); // e_shoff
            ulong shoff = br.ReadUInt64();

            fs.Seek(0x3A, SeekOrigin.Begin); // e_shentsize
            ushort shentsize = br.ReadUInt16();
            ushort shnum = br.ReadUInt16();
            ushort shstrndx = br.ReadUInt16();

            var sections = new List<(uint nameOff, uint type, ulong offset, ulong size, ulong link, ulong entsize)>();

            for (int i = 0; i < shnum; i++)
            {
                fs.Seek((long)(shoff + (ulong)(i * shentsize)), SeekOrigin.Begin);
                uint nameOff = br.ReadUInt32();
                uint type = br.ReadUInt32();
                /* sh_flags */
                br.ReadUInt64();
                /* sh_addr  */
                br.ReadUInt64();
                ulong offset = br.ReadUInt64();
                ulong size = br.ReadUInt64();
                uint link = br.ReadUInt32();
                /* sh_info */
                br.ReadUInt32();
                /* addralign */
                br.ReadUInt64();
                ulong entsize = br.ReadUInt64();

                sections.Add((nameOff, type, offset, size, link, entsize));
            }

            // Try .dynsym first, then fall back to .symtab
            foreach (var wantedType in new[] { SHT_DYNSYM, SHT_SYMTAB })
            {
                foreach (var sec in sections)
                {
                    if (sec.type != wantedType) continue;

                    var strTabSec = sections[(int)sec.link]; // sh_link -> associated string table
                    var symCount = sec.size / sec.entsize;

                    for (ulong i = 0; i < symCount; i++)
                    {
                        fs.Seek((long)(sec.offset + i * sec.entsize), SeekOrigin.Begin);
                        uint stName = br.ReadUInt32();
                        byte stInfo = br.ReadByte();
                        /* st_other */
                        br.ReadByte();
                        /* st_shndx */
                        br.ReadUInt16();
                        ulong stValue = br.ReadUInt64();
                        /* st_size */
                        br.ReadUInt64();

                        if (stName == 0) continue;

                        string name = ReadCString(fs, br, strTabSec.offset + stName);
                        if (name == symbolName)
                        {
                            if (stValue == 0) continue; // undefined symbol, keep scanning
                            return new IntPtr((long)(stValue));
                        }
                    }
                }
            }

            return IntPtr.Zero;
        }

        private static string ReadCString(FileStream fs, BinaryReader br, ulong offset)
        {
            var savedPos = fs.Position;
            fs.Seek((long)offset, SeekOrigin.Begin);

            var sb = new StringBuilder();
            int b;
            while ((b = fs.ReadByte()) > 0)
                sb.Append((char)b);

            fs.Position = savedPos;
            return sb.ToString();
        }
    }
}
