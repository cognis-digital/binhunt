using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace binhunt.polyglot.csharp
{
    /// <summary>
    /// Results of packer detection analysis.
    </summary>
    public sealed class PackerResult
    {
        public bool IsPacked { get; }
        
        /// <summary>Detected packer name or null if unknown.</summary>
        public string? DetectedPacker { get; }
        
        /// <summary>Confidence score 0.0-1.0</summary>
        public double Confidence { get; }
        
        /// <summary>List of evidence flags found.</summary>
        public List<string> EvidenceFlags { get; } = new();
        
        /// <summary>Raw bytes from suspicious sections (for forensics).</summary>
        public byte[]? SuspiciousBytes { get; }

        public PackerResult(bool isPacked, string? packer, double confidence, 
                           List<string> flags, byte[]? raw = null)
        {
            IsPacked = isPacked;
            DetectedPacker = packer;
            Confidence = Math.Clamp(confidence, 0.0, 1.0);
            EvidenceFlags.AddRange(flags);
            SuspiciousBytes = raw;
        }

        public override string ToString() => 
            $"PackerResult: IsPacked={IsPacked}, Packer='{DetectedPacker}', " +
            $"Confidence={Confidence:F2}, Flags={string.Join(", ", EvidenceFlags)}";
    }

    /// <summary>
    /// DOS header structure.
    */
    public sealed class DosHeader
    {
        public byte[] e_magic;       // 0x00-0x01: Magic (MZ)
        public ushort e_cblp;        // 0x02-0x03: Bytes per page
        public ushort e_cp;          // 0x04-0x05: Pages in file
        public ushort e_pr;          // 0x06-0x07: Relocations
        public ushort e_pt;          // 0x08-0x09: Checksum
        public ushort e_nreloc;      // 0x0A-0x0B: Initial reloc entries
        public ushort e_ovl;         // 0x0C-0x0D: Overlay number
        public ushort e_res1;        // 0x0E-0x0F: Reserved (3)
        public int    e_lfanew;      // 0x10-0x13: PE header offset

        public static DosHeader Read(Stream stream, long fileSize)
        {
            var buffer = new byte[64];
            stream.Position = 0;
            if (stream.Read(buffer, 0, Math.Min(64, (int)Math.Min(fileSize, 64))) < 32)
                throw new IOException("Failed to read DOS header");

            return new DosHeader
            {
                e_magic = buffer[0..2],
                e_cblp = BitConverter.ToUInt16(buffer, 2),
                e_cp = BitConverter.ToUInt16(buffer, 4),
                e_pr = BitConverter.ToUInt16(buffer, 6),
                e_pt = BitConverter.ToUInt16(buffer, 8),
                e_nreloc = BitConverter.ToUInt16(buffer, 10),
                e_ovl = BitConverter.ToUInt16(buffer, 12),
                e_res1 = BitConverter.ToUInt16(buffer, 14),
                e_lfanew = BitConverter.ToInt32(buffer, 60)
            };
        }

        public static bool IsPE(DosHeader header) => 
            header.e_magic[0] == 0x5A && header.e_magic[1] == 0x4D; // "MZ"

        public static long GetPeOffset(DosHeader header, long fileSize)
        {
            return header.IsPE ? header.e_lfanew : 0;
        }
    }

    /// <summary>
    /// NT headers (PE32/PE32+).
    */
    public sealed class NtHeaders
    {
        // PE32 magic: 0x10b, PE32+: 0x20b
        public const int MagicPe32 = 0x10b;
        public const int MagicPe32Plus = 0x20b;

        public int    Magic;          // 0x04-0x05: PE magic number
        public ushort MajorLinkerVer; // 0x06-0x07: Major linker version
        public ushort MinorLinkerVer; // 0x08-0x09: Minor linker version
        public int    SizeOfCode;    // 0x0A-0x0D: Code size
        public int    SizeOfInitializedData; // 0x0E-0x11: Initialized data size
        public int    SizeOfUninitializedData; // 0x12-0x15: Uninitialized data size
        public int    AddressOfEntryPoint; // 0x16-0x19: Entry point RVA
        public int    BaseOfCode;    // 0x1A-0x1D: Code base address
        public int    BaseOfData;    // 0x1E-0x21: Data base (PE32 only)

        public static NtHeaders Read(Stream stream, long peOffset)
        {
            var buffer = new byte[64];
            stream.Position = peOffset;
            if (stream.Read(buffer, 0, Math.Min(64, (int)Math.Min(stream.Length - peOffset, 64))) < 20)
                throw new IOException("Failed to read NT headers");

            return new NtHeaders
            {
                Magic = BitConverter.ToInt32(buffer, 4),
                MajorLinkerVer = BitConverter.ToUInt16(buffer, 6),
                MinorLinkerVer = BitConverter.ToUInt16(buffer, 8),
                SizeOfCode = BitConverter.ToInt32(buffer, 10),
                SizeOfInitializedData = BitConverter.ToInt32(buffer, 14),
                SizeOfUninitializedData = BitConverter.ToInt32(buffer, 18),
                AddressOfEntryPoint = BitConverter.ToInt32(buffer, 22),
                BaseOfCode = BitConverter.ToInt32(buffer, 26),
                BaseOfData = BitConverter.ToInt32(buffer, 30)
            };
        }

        public static bool IsPe32Plus(NtHeaders nt) => 
            nt.Magic == MagicPe32Plus;

        public static int GetHeaderSize(NtHeaders nt) => 
            nt.IsPe32Plus ? 24 : 20; // Additional fields in PE32+
    }

    /// <summary>
    /// Optional header flags and characteristics.
    */
    public sealed class OptionalHeaderFlags
    {
        public const int IMAGE_FILE_32BIT_MACHINE = 0x01;
        public const int IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x020;
        public const int IMAGE_FILE_DLL = 0x40;
        public const int IMAGE_FILE_EXECUTABLE_IMAGE = 0x040;

        // UPX characteristic flags (packed executable)
        public const int IMAGE_SUBSYSTEM_UNKNOWN = 0x00;
        public const int IMAGE_SUBSYSTEM_WINDOWS_GUI = 2;
        public const int IMAGE_SUBSYSTEM_WINDOWS_CONSOLE = 3;

        public static readonly Dictionary<int, string> SubsystemNames = new()
        {
            [IMAGE_SUBSYSTEM_UNKNOWN] = "Unknown",
            [IMAGE_SUBSYSTEM_WINDOWS_GUI] = "Windows GUI (2)",
            [IMAGE_SUBSYSTEM_WINDOWS_CONSOLE] = "Windows Console (3)"
        };

        public static string GetSubsystemName(int subsystem) => 
            SubsystemNames.TryGetValue(subsystem, out var name) ? name : $"Unknown({subsystem})";
    }

    /// <summary>
    /// Known packer signatures and their detection patterns.
    */
    internal sealed class PackerSignatures
    {
        // UPX-specific magic numbers found in DOS header or sections
        public static readonly byte[] UpxDosMagic = new byte[] { 0x14, 0xF5 };
        
        // Common string signatures (case-insensitive search)
        public static readonly Dictionary<string, double> StringSignatures = new()
        {
            ["UPX!"] = 0.95,
            ["PECompact"] = 0.92,
            ["VMProtect"] = 0.94,
            ["Themida"] = 0.93,
            ["Enigma Protector"] = 0.88,
            ["Armadillo"] = 0.85,
            ["Aspack"] = 0.87,
            ["PESerial"] = 0.82,
            ["Packers"] = 0.60,
            [".UPX."] = 0.91,
            ["uPX"] = 0.85
        };

        // UPX section header patterns (PE32+)
        public static readonly byte[] UpxSectionMagic = new byte[] { 0x4D, 0x5A, 0x00, 0x00, 0x01, 0x00 };

        // Generic compression headers that might indicate packing
        public static readonly Dictionary<byte[], double> CompressionSignatures = new()
        {
            [new byte[] { 0x50, 0x4B, 0x03, 0x04 }] = 0.75, // ZIP header (PK)
            [new byte[] { 0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00 }] = 0.72 // ZIP local file header
        };

        public static double CalculateConfidence(List<string> flags)
        {
            if (flags.Count == 0) return 0.0;

            var totalScore = 0.0;
            
            foreach (var flag in flags)
            {
                if (StringSignatures.TryGetValue(flag, out var score))
                    totalScore += score;
                else if (flag.Contains("UPX") || flag.Contains("upx"))
                    totalScore += 0.95;
                else if (flag.Contains("PECompact") || flag.Contains("pecompact"))
                    totalScore += 0.85;
                else if (flag.Contains("VMProtect") || flag.Contains("vmprotect"))
                    totalScore += 0.94;
                else if (flag.Contains("Themida") || flag.Contains("themida"))
                    totalScore += 0.93;
                else if (flag.Contains("Aspack") || flag.Contains("aspack"))
                    totalScore += 0.87;
                else if (flag.Contains("Enigma") || flag.Contains("enigma"))
                    totalScore += 0.86;
                else if (flag.Contains("Armadillo") || flag.Contains("armadillo"))
                    totalScore += 0.84;
                else if (flag.Contains("PESerial") || flag.Contains("peserial"))
                    totalScore += 0.75;
                else if (flag.Contains("UPX_SECTION") || flag.Contains("upx_section"))
                    totalScore += 0.92;
                else if (flag.Contains("ZIP_HEADER") || flag.Contains("zip_header"))
                    totalScore += 0.65;
                else if (flag.Contains("DOS_MAGIC"))
                    totalScore += 0.45;
            }

            return Math.Min(totalScore / flags.Count, 1.0);
        }

        public static string? IdentifyPacker(List<string> flags)
        {
            // Priority order: most specific first
            if (flags.Contains("UPX_SECTION") || flags.Contains("UPX_DOS_MAGIC"))
                return "UPX";
            
            foreach (var flag in flags)
            {
                if (flag.Contains("VMProtect") || flag.Contains("vmprotect"))
                    return "VMProtect";
                if (flag.Contains("Themida") || flag.Contains("themida"))
                    return "Themida";
                if (flag.Contains("PECompact") || flag.Contains("pecompact"))
                    return "PECompact";
                if (flag.Contains("Aspack") || flag.Contains("aspack"))
                    return "Aspack";
                if (flag.Contains("Enigma") || flag.Contains("enigma"))
                    return "Enigma Protector";
                if (flag.Contains("Armadillo") || flag.Contains("armadillo"))
                    return "Armadillo";
            }

            // Fallback: most common signature
            var sortedFlags = flags.OrderByDescending(f => 
                StringSignatures.ContainsKey(f) ? StringSignatures[f] : 0.5).ToList();
            
            if (sortedFlags.Count > 0 && sortedFlags[0].Contains("UPX"))
                return "UPX";

            return null;
        }
    }

    /// <summary>
    /// Main packer detector class.
    */
    public sealed class PackerDetector
    {
        private readonly Stream _stream;
        private readonly long _fileSize;
        
        public PackerResult Detect(Stream stream, string? fileName = null)
        {
            _stream = stream;
            _fileSize = stream.Length;

            var flags = new List<string>();
            var suspiciousBytes = new byte[0];

            try
            {
                // 1. Read DOS header
                DosHeader dosHeader;
                try
                {
                    dosHeader = DosHeader.Read(_stream, _fileSize);
                }
                catch (IOException)
                {
                    return new PackerResult(false, null, 0.1, flags, suspiciousBytes);
                }

                // Check DOS magic for UPX
                if (dosHeader.e_magic.SequenceEqual(UpxDosMagic))
                {
                    flags.Add("UPX_DOS_MAGIC");
                    suspiciousBytes = dosHeader.e_magic;
                }

                // 2. Read NT headers
                long peOffset = DosHeader.GetPeOffset(dosHeader, _fileSize);
                if (peOffset == 0 || peOffset >= _fileSize)
                {
                    return new PackerResult(false, null, 0.15, flags, suspiciousBytes);
                }

                NtHeaders ntHeaders;
                try
                {
                    ntHeaders = NtHeaders.Read(_stream, peOffset);
                }
                catch (IOException)
                {
                    return new PackerResult(false, null, 0.2, flags, suspiciousBytes);
                }

                // Check NT magic for PE32+
                if (NtHeaders.IsPe32Plus(ntHeaders))
                {
                    flags.Add("PE32_PLUS_MAGIC");
                }

                // 3. Read optional header to get subsystem and other attributes
                long optHeaderOffset = peOffset + NtHeaders.GetHeaderSize(ntHeaders);
                
                if (optHeaderOffset > 0 && optHeaderOffset < _fileSize)
                {
                    var optBuffer = new byte[256];
                    try
                    {
                        int bytesRead = _stream.Read(optBuffer, 0, Math.Min(256, (int)(_fileSize - optHeaderOffset)));
                        
                        if (bytesRead >= 18) // Minimum for subsystem field
                        {
                            int subsystem = BitConverter.ToInt16(optBuffer, 14);
                            
                            // Check for UPX section characteristics
                            // UPX typically sets IMAGE_FILE_DLL flag and uses specific subsystems
                            if ((optBuffer[2] & 0x80) != 0 || // IMAGE_FILE_DLL (bit 7 of char at offset 2)
                                subsystem == OptionalHeaderFlags.IMAGE_SUBSYSTEM_WINDOWS_GUI ||
                                subsystem == OptionalHeaderFlags.IMAGE_SUBSYSTEM_WINDOWS_CONSOLE)
                            {
                                flags.Add("SUSPICIOUS_OPTIONAL_HEADER");
                                
                                if ((optBuffer[2] & 0x80) != 0)
                                    flags.Add("IMAGE_FILE_DLL_FLAG");
                            }

                            // Check for UPX section header pattern in the optional header area
                            if (bytesRead >= 64 && optBuffer[0..6].SequenceEqual(UpxSectionMagic))
                            {
                                flags.Add("UPX_SECTION_MAGIC");
                            }
                        }
                    }
                    catch (IOException)
                    {
                        // Continue with available data
                    }
                }

                // 4. Scan for string signatures throughout the file
                var textSearchBuffer = new byte[65536];
                int totalRead = 0;
                
                while