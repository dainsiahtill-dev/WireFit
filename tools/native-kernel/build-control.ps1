param([Parameter(Mandatory=$true)][string]$Out)
$ErrorActionPreference='Stop'
$root=[System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$build=[System.IO.Path]::GetFullPath($Out)
if(Test-Path -LiteralPath $build){throw 'Build output must be new'}
if(-not (Test-Path -LiteralPath ([System.IO.Path]::GetDirectoryName($build)) -PathType Container)){throw 'Build parent must exist'}
$cl='C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x86\cl.exe'
$vc='C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207'
$sdk='C:\Program Files (x86)\Windows Kits\10'
$version='10.0.26100.0'
$null=New-Item -ItemType Directory -Path $build
$argv=@('/nologo','/Brepro','/c','/TP','/W4','/WX','/GS-','/GR-','/Od','/Ob0','/Zl','/Zc:wchar_t','/DWIN32_LEAN_AND_MEAN',('/I'+$vc+'\include'),('/I'+$sdk+'\Include\'+$version+'\ucrt'),('/I'+$sdk+'\Include\'+$version+'\shared'),('/I'+$sdk+'\Include\'+$version+'\um'),('/Fo'+$build+'\control.obj'),($PSScriptRoot+'\control.cpp'))
$compile=& $cl @argv 2>&1
[System.IO.File]::WriteAllText((Join-Path $build 'compile.log'), ($compile -join "`n"), [System.Text.UTF8Encoding]::new($false))
if($LASTEXITCODE -ne 0){throw ('Compilation failed: '+($compile -join "`n"))}
$link=Join-Path ([System.IO.Path]::GetDirectoryName($cl)) 'link.exe'
$linkArgs=@('/nologo','/Brepro','/machine:x86','/subsystem:console','/entry:wirefit_control_entry','/nodefaultlib','/dynamicbase','/nxcompat',('/def:'+$PSScriptRoot+'\control.def'),('/out:'+$build+'\wirefit-kernel-control.exe'),('/libpath:'+$sdk+'\Lib\'+$version+'\um\x86'),'kernel32.lib',($build+'\control.obj'))
$linked=& $link @linkArgs 2>&1
[System.IO.File]::WriteAllText((Join-Path $build 'link.log'), ($linked -join "`n"), [System.Text.UTF8Encoding]::new($false))
if($LASTEXITCODE -ne 0){throw ('Link failed: '+($linked -join "`n"))}
$files=@(($PSScriptRoot+'\control.cpp'),($PSScriptRoot+'\control.def'),$PSCommandPath,$cl,$link,(Join-Path $build 'wirefit-kernel-control.exe'))
$identities=@($files | ForEach-Object { $f=Get-Item -LiteralPath $_; @{path=$f.FullName;size_bytes=$f.Length;sha256=(Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash.ToLowerInvariant()} })
$record=@{schema_version=1;kind='owned_native_control_build';compiler=$cl;compile_args=$argv;linker=$link;link_args=$linkArgs;files=$identities;target_executed=$false}
[System.IO.File]::WriteAllText((Join-Path $build 'build.json'), ($record|ConvertTo-Json -Depth 16), [System.Text.UTF8Encoding]::new($false))
$record|ConvertTo-Json -Depth 16