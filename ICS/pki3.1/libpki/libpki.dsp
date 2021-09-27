# Microsoft Developer Studio Project File - Name="libpki" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=libpki - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "libpki.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "libpki.mak" CFG="libpki - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "libpki - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "libpki - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName "libpki"
# PROP Scc_LocalPath "."
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "libpki - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_LIB" /YX /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "../../../cis/build/include/cis-2.4" /I "../../include" /I "general_c" /I "general_c++" /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_LIB" /YX /FD /c
# ADD BASE RSC /l 0x412 /d "NDEBUG"
# ADD RSC /l 0x412 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo /out:"../../build/win32/release/lib/libpki.lib"

!ELSEIF  "$(CFG)" == "libpki - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /YX /FD /GZ /c
# ADD CPP /nologo /MDd /W3 /Gm /GX /ZI /Od /I "../../../cis" /I "../../../cis/cc" /I "../../../cis/cc/mint" /I "../../../cis/cc/pkcrypt" /I "../../../cis/me" /I "../../../cis/me/compress" /I "../../../cis/ckm" /I "../../../cis/sp" /I "../../../cis/sp/qsl" /I "../../include" /I "general_c" /I "general_c++" /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /YX /FD /GZ /c
# ADD BASE RSC /l 0x412 /d "_DEBUG"
# ADD RSC /l 0x412 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo /out:"../../build/win32/debug/lib/libpki.lib"

!ENDIF 

# Begin Target

# Name "libpki - Win32 Release"
# Name "libpki - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=".\general_c++\BasicCommand.cpp"
# End Source File
# Begin Source File

SOURCE=".\general_c++\LabeledValues.cpp"
# End Source File
# Begin Source File

SOURCE=".\general_c++\LdapEntry.cpp"
# End Source File
# Begin Source File

SOURCE=".\general_c++\NetworkCommand.cpp"
# End Source File
# Begin Source File

SOURCE=".\general_c++\QSLSocket.cpp"
# End Source File
# Begin Source File

SOURCE=".\general_c++\RequestCommandValues.cpp"
# End Source File
# Begin Source File

SOURCE=".\general_c++\ResponseCommandValues.cpp"
# End Source File
# Begin Source File

SOURCE=".\general_c++\Socket.cpp"
# End Source File
# Begin Source File

SOURCE=.\general_c\SocketHelper.c
# End Source File
# Begin Source File

SOURCE=.\general_c\Trace.c
# End Source File
# Begin Source File

SOURCE=".\general_c++\TypedValues.cpp"
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=".\general_c++\BasicCommand.hpp"
# End Source File
# Begin Source File

SOURCE=".\general_c++\LabeledValues.hpp"
# End Source File
# Begin Source File

SOURCE=".\general_c++\LdapEntry.hpp"
# End Source File
# Begin Source File

SOURCE=".\general_c++\NetworkCommand.hpp"
# End Source File
# Begin Source File

SOURCE=".\general_c++\QSLSocket.hpp"
# End Source File
# Begin Source File

SOURCE=".\general_c++\RequestCommandValues.hpp"
# End Source File
# Begin Source File

SOURCE=".\general_c++\ResponseCommandValues.hpp"
# End Source File
# Begin Source File

SOURCE=".\general_c++\Socket.hpp"
# End Source File
# Begin Source File

SOURCE=.\general_c\SocketHelper.h
# End Source File
# Begin Source File

SOURCE=.\general_c\Trace.h
# End Source File
# Begin Source File

SOURCE=".\general_c++\TypedValues.hpp"
# End Source File
# End Group
# Begin Group "zlib"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\..\util\compress\internal\adler32.c
# End Source File
# Begin Source File

SOURCE=..\..\..\util\compress\internal\compress.c
# End Source File
# Begin Source File

SOURCE=..\..\..\util\compress\internal\crc32.c
# End Source File
# Begin Source File

SOURCE=..\..\..\util\compress\internal\deflate.c
# End Source File
# Begin Source File

SOURCE=..\..\..\util\compress\internal\deflate.h
# End Source File
# Begin Source File

SOURCE=..\..\..\util\compress\internal\gzio.c
# End Source File
# Begin Source File

SOURCE=..\..\..\util\compress\internal\infblock.c
# End Source File
# Begin Source File

SOURCE=..\..\..\util\compress\internal\infblock.h
# End Source File
# Begin Source File

SOURCE=..\..\..\util\compress\internal\infcodes.c
# End Source File
# Begin Source File

SOURCE=..\..\..\util\compress\internal\infcodes.h
# End Source File
# Begin Source File

SOURCE=..\..\..\util\compress\internal\inffast.c
# End Source File
# Begin Source File

SOURCE=..\..\..\util\compress\internal\inffast.h
# End Source File
# Begin Source File

SOURCE=..\..\..\util\compress\internal\inffixed.h
# End Source File
# Begin Source File

SOURCE=..\..\..\util\compress\internal\inflate.c
# End Source File
# Begin Source File

SOURCE=..\..\..\util\compress\internal\inftrees.c
# End Source File
# Begin Source File

SOURCE=..\..\..\util\compress\internal\inftrees.h
# End Source File
# Begin Source File

SOURCE=..\..\..\util\compress\internal\infutil.c
# End Source File
# Begin Source File

SOURCE=..\..\..\util\compress\internal\infutil.h
# End Source File
# Begin Source File

SOURCE=..\..\..\util\compress\internal\trees.c
# End Source File
# Begin Source File

SOURCE=..\..\..\util\compress\internal\trees.h
# End Source File
# Begin Source File

SOURCE=..\..\..\util\compress\internal\uncompr.c
# End Source File
# Begin Source File

SOURCE=..\..\..\util\compress\unzip.c
# End Source File
# Begin Source File

SOURCE=..\..\..\util\compress\internal\zconf.h
# End Source File
# Begin Source File

SOURCE=..\..\..\util\compress\zip.c
# End Source File
# Begin Source File

SOURCE=..\..\..\util\compress\zip.h
# End Source File
# Begin Source File

SOURCE=..\..\..\util\compress\internal\zlib.h
# End Source File
# Begin Source File

SOURCE=..\..\..\util\compress\internal\zutil.c
# End Source File
# Begin Source File

SOURCE=..\..\..\util\compress\internal\zutil.h
# End Source File
# End Group
# End Target
# End Project
