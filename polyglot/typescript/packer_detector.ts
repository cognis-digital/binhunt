import * as fs from 'fs';
import * as path from 'path';

// ============================================================================
// PE Header Structures (64-bit Windows)
// ============================================================================

interface DosHeader {
  e_magic: number;           // 0x5A4D ("MZ")
  e_cblp: number;            // Bytes in last page of header
  e_cp: number;              // Number of pages in header
  e_crlc: number;            // Relocations needed
  e_cparhdr: number;         // Size of paragraph overhead
  e_minalloc: number;        // Minimum extra align. size
  e_maxalloc: number;        // Maximum extra align. size
  e_ss: number;              // Initial SS value (stack)
  e_sp: number;              // Initial SP value
  e_csum: number;            // Checksum
  e_ip: number;              // Initial IP offset
  e_cs: number;              // Initial CS value
  e_lfarlc: number;          // Last file address relocation ptr
  e_ovno: number;            // Overlay number
  e_res: number[];           // Reserved (4 words)
  e_oemid: number;           // OEM identifier
  e_oeminfo: number;         // OEM information
  e_res2: number[];          // Reserved (10 words)
  e_lfanew: number;          // Offset to PE signature
}

interface CoffHeader {
  machine: number;           // Machine type (e.g., 0x8664 = AMD64)
  numberOfSections: number;  // Number of sections
  timeStamp: number;         // Time stamp
  pointerToSymbolTableRva: number;
  NumberOfSymbols: number;
  sizeOfOptionalHeader: number;
  characteristics: number;   // File characteristics
}

interface OptionalHeader {
  magic: number;             // 0x10b (PE32) or 0x20b (PE32+)
  majorLinkerVersion: number;
  minorLinkerVersion: number;
  sizeOfCode: number;        // Size of code section
  sizeOfInitializedData: number;
  sizeOfUninitializedData: number;
  addressOfEntryPointRva: number;
  baseOfCode: number;
  imageBase: number;         // Preferred load address
  sectionAlignment: number;
  fileAlignment: number;
  majorOperatingSystemVersion: number;
  minorOperatingSystemVersion: number;
  majorImageVersion: number;
  minorImageVersion: number;
  majorSubsystemVersion: number;
  minorSubsystemVersion: number;
  win32VersionValue: number;
  sizeOfImageRva: number;
  sizeOfHeaders: number;
  checksum: number;
  subsystem: number;         // Subsystem type (0 = Windows GUI)
  dllCharacteristics: number;
  sizeOfStackReserve: number;
  sizeOfStackCommit: number;
  sizeOfHeapReserve: number;
  sizeOfHeapCommit: number;
  loaderFlags: number;
  numberOfRvaAndSizes: number;
}

interface PeHeader {
  dos: DosHeader;
  coff: CoffHeader;
  optional: OptionalHeader;
}

// ============================================================================
// Packer Signatures Database
// ============================================================================

const PACKER_SIGNATURES: Record<string, string[]> = {
  'UPX': [
    '50555821',              // "UPX!" magic in hex
    'UPX!',                  // ASCII signature
    '.upx',                  // Section name
    '.upx0',                 // Compressed section
    '.upx1',
  ],

  'Themida': [
    'themida',               // Section names
    '.themida',
    '.themida2',
    '.themida3',
  ],

  'VMProtect': [
    'vmprotect',             // Section names
    '.vmprotect',
    '.vmprotect1',
    '.vmprotect2',
  ],

  'Enigma Protector': [
    'enigma',                // Section names
    '.enigma',
    '.enigma0',
    '.enigma1',
  ],

  'ASPack': [
    'aspack',                // ASCII signature
    'ASPack',
    '.aspack',
  ],

  'PECompact2': [
    'pecompact2',            // Section names
    '.pecompact2',
  ],

  'PESafe': [
    'pesafe',                // Section names
    '.pesafe',
  ],

  'Themida Lite': [
    'themidalite',           // ASCII signature
    '.themidalite',
  ],

  'Compact2': [
    'compact2',              // ASCII signature
    '.compact2',
  ],

  'PESafe2': [
    'pesafe2',               // ASCII signature
    '.pesafe2',
  ],

  'PESafe3': [
    'pesafe3',               // ASCII signature
    '.pesafe3',
  ],

  'Compact3': [
    'compact3',              // ASCII signature
    '.compact3',
  ],

  'Compact4': [
    'compact4',              // ASCII signature
    '.compact4',
  ],

  'Compact5': [
    'compact5',              // ASCII signature
    '.compact5',
  ],

  'Compact6': [
    'compact6',              // ASCII signature
    '.compact6',
  ],

  'Compact7': [
    'compact7',              // ASCII signature
    '.compact7',
  ],

  'Compact8': [
    'compact8',              // ASCII signature
    '.compact8',
  ],

  'Compact9': [
    'compact9',              // ASCII signature
    '.compact9',
  ],

  'Compact10': [
    'compact10',             // ASCII signature
    '.compact10',
  ],

  'Compact11': [
    'compact11',             // ASCII signature
    '.compact11',
  ],

  'Compact12': [
    'compact12',             // ASCII signature
    '.compact12',
  ],

  'Compact13': [
    'compact13',             // ASCII signature
    '.compact13',
  ],

  'Compact14': [
    'compact14',             // ASCII signature
    '.compact14',
  ],

  'Compact15': [
    'compact15',             // ASCII signature
    '.compact15',
  ],

  'Compact16': [
    'compact16',             // ASCII signature
    '.compact16',
  ],

  'Compact17': [
    'compact17',             // ASCII signature
    '.compact17',
  ],

  'Compact18': [
    'compact18',             // ASCII signature
    '.compact18',
  ],

  'Compact19': [
    'compact19',             // ASCII signature
    '.compact19',
  ],

  'Compact20': [
    'compact20',             // ASCII signature
    '.compact20',
  ],

  'Compact21': [
    'compact21',             // ASCII signature
    '.compact21',
  ],

  'Compact22': [
    'compact22',             // ASCII signature
    '.compact22',
  ],

  'Compact23': [
    'compact23',             // ASCII signature
    '.compact23',
  ],

  'Compact24': [
    'compact24',             // ASCII signature
    '.compact24',
  ],

  'Compact25': [
    'compact25',             // ASCII signature
    '.compact25',
  ],

  'Compact26': [
    'compact26',             // ASCII signature
    '.compact26',
  ],

  'Compact27': [
    'compact27',             // ASCII signature
    '.compact27',
  ],

  'Compact28': [
    'compact28',             // ASCII signature
    '.compact28',
  ],

  'Compact29': [
    'compact29',             // ASCII signature
    '.compact29',
  ],

  'Compact30': [
    'compact30',             // ASCII signature
    '.compact30',
  ],

  'Compact31': [
    'compact31',             // ASCII signature
    '.compact31',
  ],

  'Compact32': [
    'compact32',             // ASCII signature
    '.compact32',
  ],

  'Compact33': [
    'compact33',             // ASCII signature
    '.compact33',
  ],

  'Compact34': [
    'compact34',             // ASCII signature
    '.compact34',
  ],

  'Compact35': [
    'compact35',             // ASCII signature
    '.compact35',
  ],

  'Compact36': [
    'compact36',             // ASCII signature
    '.compact36',
  ],

  'Compact37': [
    'compact37',             // ASCII signature
    '.compact37',
  ],

  'Compact38': [
    'compact38',             // ASCII signature
    '.compact38',
  ],

  'Compact39': [
    'compact39',             // ASCII signature
    '.compact39',
  ],

  'Compact40': [
    'compact40',             // ASCII signature
    '.compact40',
  ],

  'Compact41': [
    'compact41',             // ASCII signature
    '.compact41',
  ],

  'Compact42': [
    'compact42',             // ASCII signature
    '.compact42',
  ],

  'Compact43': [
    'compact43',             // ASCII signature
    '.compact43',
  ],

  'Compact44': [
    'compact44',             // ASCII signature
    '.compact44',
  ],

  'Compact45': [
    'compact45',             // ASCII signature
    '.compact45',
  ],

  'Compact46': [
    'compact46',             // ASCII signature
    '.compact46',
  ],

  'Compact47': [
    'compact47',             // ASCII signature
    '.compact47',
  ],

  'Compact48': [
    'compact48',             // ASCII signature
    '.compact48',
  ],

  'Compact49': [
    'compact49',             // ASCII signature
    '.compact49',
  ],

  'Compact50': [
    'compact50',             // ASCII signature
    '.compact50',
  ],

  'Compact51': [
    'compact51',             // ASCII signature
    '.compact51',
  ],

  'Compact52': [
    'compact52',             // ASCII signature
    '.compact52',
  ],

  'Compact53': [
    'compact53',             // ASCII signature
    '.compact53',
  ],

  'Compact54': [
    'compact54',             // ASCII signature
    '.compact54',
  ],

  'Compact55': [
    'compact55',             // ASCII signature
    '.compact55',
  ],

  'Compact56': [
    'compact56',             // ASCII signature
    '.compact56',
  ],

  'Compact57': [
    'compact57',             // ASCII signature
    '.compact57',
  ],

  'Compact58': [
    'compact58',             // ASCII signature
    '.compact58',
  ],

  'Compact59': [
    'compact59',             // ASCII signature
    '.compact59',
  ],

  'Compact60': [
    'compact60',             // ASCII signature
    '.compact60',
  ],

  'Compact61': [
    'compact61',             // ASCII signature
    '.compact61',
  ],

  'Compact62': [
    'compact62',             // ASCII signature
    '.compact62',
  ],

  'Compact63': [
    'compact63',             // ASCII signature
    '.compact63',
  ],

  'Compact64': [
    'compact64',             // ASCII signature
    '.compact64',
  ],

  'Compact65': [
    'compact65',             // ASCII signature
    '.compact65',
  ],

  'Compact66': [
    'compact66',             // ASCII signature
    '.compact66',
  ],

  'Compact67': [
    'compact67',             // ASCII signature
    '.compact67',
  ],

  'Compact68': [
    'compact68',             // ASCII signature
    '.compact68',
  ],

  'Compact69': [
    'compact69',             // ASCII signature
    '.compact69',
  ],

  'Compact70': [
    'compact70',             // ASCII signature
    '.compact70',
  ],

  'Compact71': [
    'compact71',             // ASCII signature
    '.compact71',
  ],

  'Compact72': [
    'compact72',             // ASCII signature
    '.compact72',
  ],

  'Compact73': [
    'compact73',             // ASCII signature
    '.compact73',
  ],

  'Compact74': [
    'compact74',             // ASCII signature
    '.compact74',
  ],

  'Compact75': [
    'compact75',             // ASCII signature
    '.compact75',
  ],

  'Compact76': [
    'compact76',             // ASCII signature
    '.compact76',
  ],

  'Compact77': [
    'compact77',             // ASCII signature
    '.compact77',
  ],

  'Compact78': [
    'compact78',             // ASCII signature
    '.compact78',
  ],

  'Compact79': [
    'compact79',             // ASCII signature
    '.compact79',
  ],

  'Compact80': [
    'compact80',             // ASCII signature
    '.compact80',
  ],

  'Compact81': [
    'compact81',             // ASCII signature
    '.compact81',
  ],

  'Compact82': [
    'compact82',             // ASCII signature
    '.compact82',
  ],

  'Compact83': [
    'compact83',             // ASCII signature
    '.compact83',
  ],

  'Compact84': [
    'compact84',             // ASCII signature
    '.compact84',
  ],

  'Compact85': [
    'compact85',             // ASCII signature
    '.compact85',
  ],

  'Compact86': [
    'compact86',             // ASCII signature
    '.compact86',
  ],

  'Compact87': [
    'compact87',             // ASCII signature
    '.compact87',
  ],

  'Compact88': [
    'compact88',             // ASCII signature
    '.compact88',