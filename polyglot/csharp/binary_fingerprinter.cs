using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Diagnostics;

namespace binhunt
{
    /// <summary>
    /// Represents a known-good baseline for comparison.
    /// </summary>
    public class Baseline
    {
        public string FileName { get; set; } = "";
        public byte[] RawBytes { get; set; } = [];
        public Dictionary<string, object> Metadata { get; set; } = new();
        public string? PackerSignature { get; set; }

        public static Baseline Create(string path)
        {
            var baseline = new Baseline
            {
                FileName = Path.GetFileName(path),
                RawBytes = File.ReadAllBytes(path)
            };

            if (File.Exists(path))
            {
                using var stream = File.OpenRead(path);
                var reader = new BinaryReader(stream, Encoding.ASCII);
                
                // Extract PE metadata
                baseline.Metadata["DosHeader"] = ReadDosHeader(reader);
                baseline.Metadata["PeHeader"] = ReadPeHeader(reader);
                baseline.Metadata["OptionalHeader"] = ReadOptionalHeader(reader);

                // Calculate hashes
                var md5Hash = CalculateHash(stream, "MD5");
                var sha1Hash = CalculateHash(stream, "SHA1");
                var sha256Hash = CalculateHash(stream, "SHA256");
                
                baseline.Metadata["MD5"] = md5Hash;
                baseline.Metadata["SHA1"] = sha1Hash;
                baseline.Metadata["SHA256"] = sha256Hash;

                // Detect packer
                var packerInfo = PackerDetector.Analyze(stream);
                if (!string.IsNullOrEmpty(packerInfo.Signature))
                {
                    baseline.PackerSignature = packerInfo.Signature;
                    baseline.Metadata["Packer"] = packerInfo.Signature;
                }

                // Extract section info
                var sections = ReadSectionHeaders(reader);
                baseline.Metadata["Sections"] = new
                {
                    Count = sections.Count,
                    Names = string.Join(", ", sections.Select(s => s.Name))
                };
            }

            return baseline;
        }

        private static Dictionary<string, object> ReadDosHeader(BinaryReader reader)
        {
            var dos = new Dictionary<string, object>();
            
            // DOS header magic (MZ)
            string magic = reader.BaseStream.Position < 2 ? "" : 
                Encoding.ASCII.GetString(reader.ReadBytes(2));
            dos["Magic"] = magic;

            // PE offset
            int peOffset = reader.ReadInt32();
            dos["PE_Offset"] = peOffset;

            return dos;
        }

        private static Dictionary<string, object> ReadPeHeader(BinaryReader reader)
        {
            var pe = new Dictionary<string, object>();
            
            // PE signature (PE0000)
            string sig = reader.BaseStream.Position < 64 ? "" : 
                Encoding.ASCII.GetString(reader.ReadBytes(2));
            pe["Signature"] = sig;

            // Machine type
            ushort machine = reader.ReadUInt16();
            pe["Machine"] = machine;
            pe["MachineName"] = GetMachineName(machine);

            return pe;
        }

        private static Dictionary<string, object> ReadOptionalHeader(BinaryReader reader)
        {
            var opt = new Dictionary<string, object>();
            
            // Magic (PE32 vs PE32+)
            ushort magic = reader.ReadUInt16();
            opt["Magic"] = magic;
            opt["IsPE32Plus"] = magic == 0x20b ?? false;

            // Entry point RVA
            uint entryPointRva = reader.ReadUInt32();
            opt["EntryPoint_RVA"] = entryPointRva;

            // Image base (for PE32)
            if (magic == 0x10b)
            {
                uint imageBase = reader.ReadUInt32();
                opt["ImageBase"] = imageBase;
            }

            return opt;
        }

        private static string GetMachineName(ushort machine)
        {
            switch (machine)
            {
                case 0x14c: return "i386";
                case 0x8664: return "AMD x64";
                case 0xaa: return "ARM";
                case 0xb2: return "ARM64";
                default: return $"Unknown (0x{machine:X})";
            }
        }

        private static List<SectionInfo> ReadSectionHeaders(BinaryReader reader)
        {
            var sections = new List<SectionInfo>();
            
            // Number of sections is at offset 60 in PE header
            int numSections = reader.ReadInt32();
            
            for (int i = 0; i < numSections && reader.BaseStream.Position < reader.BaseStream.Length - 40; i++)
            {
                var name = Encoding.ASCII.GetString(reader.ReadBytes(8)).TrimEnd('\0');
                var virtualSize = reader.ReadUInt32();
                var virtualAddress = reader.ReadUInt32();
                var rawSize = reader.ReadUInt32();
                var rawDataPtr = reader.ReadUInt32();
                
                sections.Add(new SectionInfo
                {
                    Name = name,
                    VirtualSize = virtualSize,
                    VirtualAddress = virtualAddress,
                    RawSize = rawSize,
                    RawDataPtr = rawDataPtr
                });
            }

            return sections;
        }

        private static string CalculateHash(Stream stream, string algorithm)
        {
            using var sha = CreateSha(algorithm);
            
            // Reset to beginning if needed (for multiple reads)
            stream.Position = 0;
            
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                sha.TransformBlock(buffer, 0, bytesRead, buffer, 0);
            }
            sha.TransformFinalBlock(new byte[0], 0, 0);
            
            return BitConverter.ToString(sha.Hash).Replace("-", "").ToLower();
        }

        private static System.Security.Cryptography.SHA CreateSha(string algorithm)
        {
            switch (algorithm.ToLower())
            {
                case "md5":
                    return new System.Security.Cryptography.MD5CryptoServiceProvider();
                case "sha1":
                    return new System.Security.Cryptography.SHA1CryptoServiceProvider();
                case "sha256":
                    return new System.Security.Cryptography.SHA256Managed();
                default:
                    throw new ArgumentException($"Unknown hash algorithm: {algorithm}");
            }
        }

        /// <summary>
        /// Main fingerprinter class.
        /// </summary>
        public class Fingerprinter
        {
            private readonly string _toolName = "binhunt";
            
            public FingerprintResult Analyze(string path)
            {
                if (!File.Exists(path))
                    throw new FileNotFoundException($"Binary not found: {path}");

                using var stream = File.OpenRead(path);
                var reader = new BinaryReader(stream, Encoding.ASCII);

                // 1. Basic file info
                var fileInfo = new FileInfo(path);
                
                // 2. DOS header check
                if (stream.Position < 64)
                {
                    string dosMagic = Encoding.ASCII.GetString(reader.ReadBytes(2));
                    if (!dosMagic.StartsWith("MZ"))
                        return new FingerprintResult
                        {
                            Path = path,
                            Size = fileInfo.Length,
                            IsPE = false,
                            DosMagic = dosMagic,
                            Message = "Not a PE executable"
                        };
                }

                // 3. PE header check
                int peOffset = reader.ReadInt32();
                if (stream.Position < peOffset + 64)
                {
                    string peSig = Encoding.ASCII.GetString(reader.ReadBytes(2));
                    if (!peSig.StartsWith("PE"))
                        return new FingerprintResult
                        {
                            Path = path,
                            Size = fileInfo.Length,
                            IsPE = false,
                            PeOffset = peOffset,
                            PeSignature = peSig,
                            Message = "Not a valid PE executable"
                        };
                }

                // 4. Extract metadata
                var dosHeader = ReadDosHeader(reader);
                var peHeader = ReadPeHeader(reader);
                var optionalHeader = ReadOptionalHeader(reader);
                
                // 5. Get sections
                var sectionHeaders = ReadSectionHeaders(reader);
                
                // 6. Detect packers
                var packerInfo = PackerDetector.Analyze(stream);

                // 7. Calculate hashes
                stream.Position = 0;
                var md5Hash = CalculateHash(stream, "MD5");
                var sha1Hash = CalculateHash(stream, "SHA1");
                var sha256Hash = CalculateHash(stream, "SHA256");

                // 8. Build result
                return new FingerprintResult
                {
                    Path = path,
                    Size = fileInfo.Length,
                    IsPE = true,
                    DosMagic = dosHeader["Magic"]?.ToString() ?? "",
                    PeOffset = peOffset,
                    PeSignature = peHeader["Signature"]?.ToString() ?? "",
                    Machine = peHeader["MachineName"]?.ToString() ?? "Unknown",
                    Magic = optionalHeader["Magic"].ToString(),
                    IsPE32Plus = bool.Parse(optionalHeader["IsPE32Plus"].ToString()),
                    EntryPointRva = optionalHeader["EntryPoint_RVA"],
                    MD5 = md5Hash,
                    SHA1 = sha1Hash,
                    SHA256 = sha256Hash,
                    SectionsCount = sectionHeaders.Count,
                    SectionNames = string.Join(", ", 
                        sectionHeaders.Select(s => s.Name).Distinct().Take(10)),
                    PackerSignature = packerInfo.Signature,
                    Metadata = new Dictionary<string, object>
                    {
                        ["DosHeader"] = dosHeader,
                        ["PeHeader"] = peHeader,
                        ["OptionalHeader"] = optionalHeader,
                        ["Sections"] = sectionHeaders.Count,
                        ["MD5"] = md5Hash,
                        ["SHA1"] = sha1Hash,
                        ["SHA256"] = sha256Hash,
                    },
                    PackerInfo = packerInfo
                };
            }

            public FingerprintResult CompareAgainstBaseline(string path, Baseline baseline)
            {
                var result = Analyze(path);
                
                // Check hash match
                bool md5Match = string.Equals(result.MD5, baseline.Metadata["MD5"]?.ToString(), 
                    StringComparison.OrdinalIgnoreCase);
                bool sha1Match = string.Equals(result.SHA1, baseline.Metadata["SHA1"]?.ToString(), 
                    StringComparison.OrdinalIgnoreCase);
                bool sha256Match = string.Equals(result.SHA256, baseline.Metadata["SHA256"]?.ToString(), 
                    StringComparison.OrdinalIgnoreCase);

                // Check packer match
                bool packerMatch = string.Equals(
                    result.PackerSignature, 
                    baseline.PackerSignature, 
                    StringComparison.OrdinalIgnoreCase) ||
                    (result.PackerSignature == null && baseline.PackerSignature == null);

                // Check section count and names
                var baselineSections = baseline.Metadata["Sections"] as System.Collections.IDictionary;
                bool sectionsMatch = baselineSections != null && 
                    ((int)baselineSections["Count"] == result.SectionsCount ||
                     string.Equals(baselineSections["Names"]?.ToString(), result.SectionNames, 
                        StringComparison.OrdinalIgnoreCase));

                // Determine integrity status
                int mismatches = 0;
                if (!md5Match) mismatches++;
                if (!sha1Match) mismatches++;
                if (!sha256Match) mismatches++;
                if (!packerMatch) mismatches++;
                if (sectionsMatch == false) mismatches++;

                string status = "INTACT";
                string details = "";

                if (mismatches > 0)
                {
                    status = "MODIFIED";
                    
                    var changes = new List<string>();
                    
                    if (!md5Match)
                        changes.Add($"MD5: {result.MD5} vs {baseline.Metadata[\"MD5\"]}");
                    if (!sha1Match)
                        changes.Add($"SHA1: {result.SHA1} vs {baseline.Metadata[\"SHA1\"]}");
                    if (!sha256Match)
                        changes.Add($"SHA256: {result.SHA256} vs {baseline.Metadata[\"SHA256\"]}");
                    
                    if (packerMatch == false && result.PackerSignature != null)
                        changes.Add($"Packer changed: {result.PackerSignature} vs {baseline.PackerSignature ?? \"none\"}");
                    
                    details = string.Join("; ", changes);
                }

                return new FingerprintResult
                {
                    Path = path,
                    Size = result.Size,
                    IsPE = result.IsPE,
                    MD5 = result.MD5,
                    SHA1 = result.SHA1,
                    SHA256 = result.SHA256,
                    PackerSignature = result.PackerSignature,
                    SectionsCount = result.SectionsCount,
                    Status = status,
                    Mismatches = mismatches,
                    Details = details,
                    BaselineMatched = mismatches == 0
                };
            }

            public FingerprintResult Diff(string path1, string path2)
            {
                var baseline = Baseline.Create(path1);
                var current = Analyze(path2);
                
                return CompareAgainstBaseline(path2, baseline);
            }
        }

        /// <summary>
        /// Detects common packers and obfuscators.
        /// </summary>
        public class PackerDetector
        {
            private static readonly Dictionary<string, string> PACKER_SIGNATURES = new()
            {
                // UPX packer signatures
                ["UPX1"] = "UPX!",
                ["UPX2"] = "UPX0",
                
                // ASPack (PECompact)
                ["ASPack"] = "PCC1",
                
                // Themida
                ["Themida"] = "THEMIDA",
                
                // VMProtect
                ["VMProtect"] = "VMPROTECT",
                
                // Enigma Protector
                ["Enigma"] = "ENIGMA",
                
                // PECompact2
                ["PECompact2"] = "PCC2",
                
                // ASPack3 (ASPack v3)
                ["ASPack3"] = "PCC3",
            };

            public static PackerInfo Analyze(Stream stream)
            {
                var info = new PackerInfo();
                
                try
                {
                    using var reader = new BinaryReader(stream, Encoding.ASCII);
                    
                    // 1. Check DOS header for UPX magic
                    if (stream.Position < 64)
                    {
                        string dosMagic = Encoding.ASCII.GetString(reader.ReadBytes(2));
                        
                        if (dosMagic == "UPX!" || dosMagic == "UPX0")
                        {
                            info.Signature = "UPX";
                            info.Version = dosMagic == "UPX1" ? 1 : 2;
                            info.Description = "Ultimate Packer for eXecutables (UPX)";
                            return info;
                        }
                    }

                    // 2. Check PE header offset for UPX magic
                    int peOffset = reader.ReadInt32();
                    
                    if (stream.Position < peOffset + 64)
                    {
                        string peSig = Encoding.ASCII.GetString(reader.ReadBytes(2));
                        
                        if (peSig == "UPX1" || peSig == "UPX0")
                        {
                            info.Signature = "UPX";
                            info.Version = peSig == "UPX1" ? 1 : 2;
                            info.Description = "Ultimate Packer for eXecutables (UPX)";
                            return info;
                        }
                    }

                    // 3. Check section names for packer signatures
                    int numSections = reader.ReadInt32();
                    
                    if (numSections > 0 && stream.Position < peOffset + 64 + numSections * 40)
                    {
                        var sections = new List<SectionInfo>();
                        
                        for (int i = 0; i < numSections; i++)
                        {
                            string name = Encoding.ASCII.GetString(reader.ReadBytes(8)).TrimEnd('\0');
                            
                            // Check for packer section names
                            if (name.StartsWith("UPX") || name == "UPX" || 
                                name.Contains(".upx") || name.Contains(".UPX"))
                            {
                                info.Signature = "UPX";
                                info.Description = "Ultimate Packer for eXec