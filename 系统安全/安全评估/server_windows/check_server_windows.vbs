Dim argu_count, args_dic, uuid
uuid = split(WScript.ScriptName, ".")(0)
argu_count = 0
set args_dic = CreateObject("Scripting.Dictionary")
if WScript.Arguments.Count < argu_count then
WScript.Echo "Usage:" & uuid & ".vbs" 
wscript.quit
end if

dim obj_shell
set obj_shell = createobject("wscript.shell")

dim init_cmd(1)
init_cmd(0) = obj_shell.run("cmd /c secedit /export /cfg %tmp%\sec.log & CHCP 936", 0, True)

Dim pre_cmd_dic
set pre_cmd_dic = CreateObject("Scripting.Dictionary")
pre_cmd_dic.Add "201"  , "cmd /c (secedit /export /cfg sec.inf /quiet)&(type sec.inf|find ""AuditObjectAccess"")&(del sec.inf) 2>&1"
pre_cmd_dic.Add "202"  , "cmd /c (secedit /export /cfg sec.inf /quiet)&(type sec.inf|findstr SeTakeOwnershipPrivilege)&(del sec.inf) 2>&1"
pre_cmd_dic.Add "203"  , "cmd /c (secedit /export /cfg sec.inf /quiet)&(type sec.inf|findstr SeShutdownPrivilege)&(del sec.inf) 2>&1"
pre_cmd_dic.Add "204"  , "cmd /c (reg query ""HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"" /v PortNumber) 2>&1"
pre_cmd_dic.Add "205"  , "cmd /c (secedit /export /cfg sec.inf /quiet)&(type sec.inf|find ""PasswordHistorySize"")&(del sec.inf) 2>&1"
pre_cmd_dic.Add "206"  , "cmd /c (FOR /F %i IN ('wmic share get Path') DO @CACLS %i 2>nul) 2>&1"
pre_cmd_dic.Add "207"  , "cmd /c (secedit /export /cfg sec_EventAudit.inf)&(type sec_EventAudit.inf|findstr ""^Audit"")&(del sec_EventAudit.inf) 2>&1"
pre_cmd_dic.Add "208"  , "cmd /c (wmic NICCONFIG get IPAddress,IPEnabled,IPFilterSecurityEnabled,IPSecPermitIPProtocols,IPSecPermitTCPPorts,IPSecPermitUDPPorts|findstr ""TRUE IPAddress"") 2>&1"
pre_cmd_dic.Add "209"  , "cmd /c (reg query ""HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters""|findstr /I ""AutoShareServer"")&(reg query ""HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters""|findstr /I ""AutoShareWKS"")&(wmic share list  | findstr ""."") 2>&1"
pre_cmd_dic.Add "210"  , "cmd /c (secedit /export /cfg sec.inf /quiet)&(type sec.inf|find ""AuditAccountManage"")&(del sec.inf) 2>&1"
pre_cmd_dic.Add "211"  , "cmd /c (reg query ""HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters""|findstr /I ""SynAttackProtect TcpMaxPortsExhausted TcpMaxHalfOpen TcpMaxHalfOpenRetried"") 2>&1"
pre_cmd_dic.Add "212"  , "cmd /c (wmic nteventlog get Caption,FileSize,MaxFileSize,OverWritePolicy  | findstr ""."")&(reg query ""HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Application"" /v Retention || echo Retention notfound not config)&(reg query ""HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\System"" /v Retention || echo Retention notfound not config)&(reg query ""HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security"" /v Retention || echo Retention notfound not config) 2>&1"
pre_cmd_dic.Add "213"  , "cmd /c (net user guest) 2>&1"
pre_cmd_dic.Add "214"  , "cmd /c (secedit /export /cfg sec.inf /quiet)&(type sec.inf|find ""AuditProcessTracking"")&(del sec.inf) 2>&1"
pre_cmd_dic.Add "215"  , "cmd /c (secedit /export /cfg sec.inf /quiet)&(type sec.inf|find ""AuditSystemEvents"")&(del sec.inf) 2>&1"
pre_cmd_dic.Add "216"  , "cmd /c (secedit /export /cfg sec.inf /quiet)&(type sec.inf|find ""AuditDSAccess"")&(del sec.inf) 2>&1"
pre_cmd_dic.Add "217"  , "cmd /c (secedit /export /cfg sec.inf /quiet)&(type sec.inf|find ""MaximumPasswordAge"")&(del sec.inf) 2>&1"
pre_cmd_dic.Add "218"  , "cmd /c (secedit /export /cfg sec.inf /quiet)&(type sec.inf|findstr AuditPrivilegeUse)&(del sec.inf) 2>&1"
pre_cmd_dic.Add "219"  , "cmd /c (wmic service where name=""w32time"" get state | find /i /v ""state"")&(reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\w32time\Parameters /v NtpServer || echo NtpServer notfound not config)&(wmic service where name=""w32time"" get startmode | find /i /v ""startmode"") 2>&1"
pre_cmd_dic.Add "220"  , "cmd /c ((systeminfo || wmic os get Caption,CSDVersion,ServicePackMajorVersion,ServicePackMinorVersion)|findstr /r ""^OS 修补程序 KB Service Pack"") 2>&1"
pre_cmd_dic.Add "221"  , "cmd /c (secedit /export /cfg sec.inf /quiet)&(type sec.inf|find ""AutoDisconnect"")&(del sec.inf) 2>&1"
pre_cmd_dic.Add "222"  , "cmd /c (secedit /export /cfg sec.inf /quiet)&(type sec.inf|find ""SeRemoteShutdownPrivilege"")&(del sec.inf) 2>&1"
pre_cmd_dic.Add "223"  , "cmd /c (reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer | find ""NoDriveTypeAutoRun"") 2>&1"
pre_cmd_dic.Add "224"  , "cmd /c (secedit /export /cfg sec.inf /quiet)&(type sec.inf |findstr SeNetworkLogonRight)&(del sec.inf) 2>&1"
pre_cmd_dic.Add "225"  , "cmd /c (secedit /export /cfg sec.inf /quiet)&(type sec.inf |findstr SeInteractiveLogonRight)&(del sec.inf) 2>&1"
pre_cmd_dic.Add "226"  , "cmd /c (reg query ""HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities"") 2>&1"
pre_cmd_dic.Add "227"  , "cmd /c (wmic OS Get DataExecutionPrevention_SupportPolicy  | findstr ""."") 2>&1"
pre_cmd_dic.Add "228"  , "cmd /c (net localgroup administrators|findstr /V ""^$ ^别名 ^注释 ^- ^成员 ^命令成功完成""|find /v /n ""::"") 2>&1"
pre_cmd_dic.Add "229"  , "cmd /c (tasklist) 2>&1"
pre_cmd_dic.Add "230"  , "cmd /c (secedit /export /cfg sec.inf /quiet)&(type sec.inf|find ""LockoutBadCount"")&(del sec.inf) 2>&1"
pre_cmd_dic.Add "231"  , "cmd /c (secedit /export /cfg sec.inf /quiet)&(type sec.inf|find ""PasswordComplexity"")&(del sec.inf) 2>&1"
pre_cmd_dic.Add "232"  , "cmd /c (wmic DESKTOP get  Name,ScreenSaverActive,ScreenSaverSecure,ScreenSaverTimeout|findstr /i /v ""AUTHORITY .DEFAULT"") 2>&1"
pre_cmd_dic.Add "233"  , "cmd /c (netsh firewall show state) 2>&1"
pre_cmd_dic.Add "234"  , "cmd /c (secedit /export /cfg sec.inf /quiet)&(type sec.inf|find ""LockoutDuration"")&(del sec.inf) 2>&1"
pre_cmd_dic.Add "235"  , "cmd /c (secedit /export /cfg sec.inf /quiet)&(type sec.inf|find ""ResetLockoutCount"")&(del sec.inf) 2>&1"
pre_cmd_dic.Add "236"  , "cmd /c (secedit /export /cfg sec_EventAudit.inf)&(type sec_EventAudit.inf|findstr ""^Audit"")&(del sec_EventAudit.inf) 2>&1"
pre_cmd_dic.Add "237"  , "cmd /c (net start|find /i ""Alerter"") 2>&1"
pre_cmd_dic.Add "238"  , "cmd /c (tasklist |find ""tlntsvr"") 2>&1"
pre_cmd_dic.Add "239"  , "cmd /c (net start |find ""Computer Browser"") 2>&1"
pre_cmd_dic.Add "240"  , "cmd /c (net start |find ""Cli"") 2>&1"
pre_cmd_dic.Add "241"  , "cmd /c (net start |find ""Mes"") 2>&1"
pre_cmd_dic.Add "242"  , "cmd /c (net start |find ""Remote Regis"") 2>&1"
pre_cmd_dic.Add "243"  , "cmd /c (net start |find ""Routing"") 2>&1"
pre_cmd_dic.Add "244"  , "cmd /c (net start |find ""Print"") 2>&1"
pre_cmd_dic.Add "245"  , "cmd /c (net start |find ""Automatic"") 2>&1"
pre_cmd_dic.Add "246"  , "cmd /c (net start |find ""Terminal Ser"") 2>&1"
pre_cmd_dic.Add "247"  , "cmd /c (secedit /export /cfg sec.inf /quiet)&(type sec.inf|find ""RestrictAnonymous"")&(del sec.inf) 2>&1"
pre_cmd_dic.Add "248"  , "cmd /c (secedit /export /cfg sec.inf /quiet)&(type sec.inf|find ""RestrictAnonymousSAM"")&(del sec.inf) 2>&1"
pre_cmd_dic.Add "249"  , "cmd /c (secedit /export /cfg sec.inf /quiet)&(type sec.inf|find ""DontDisplayLastUserName"")&(del sec.inf) 2>&1"
pre_cmd_dic.Add "250"  , "cmd /c (net start |find ""World Wide Web Publishing"") 2>&1"
pre_cmd_dic.Add "251"  , "cmd /c (net start |find ""Simple Mail"") 2>&1"
pre_cmd_dic.Add "252"  , "cmd /c (net start |find ""SNMP"") 2>&1"
pre_cmd_dic.Add "253"  , "cmd /c (reg query ""HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl""|findstr /I ""AutoReboot"") 2>&1"
pre_cmd_dic.Add "254"  , "cmd /c (secedit /export /cfg sec.conf)&(type sec.conf | find ""NullSess"")&(del sec.conf) 2>&1"
pre_cmd_dic.Add "255"  , "cmd /c (REG QUERY ""HKLM\System\CurrentControlSet\Control\Lsa"" /v restrictanonymous) 2>&1"
pre_cmd_dic.Add "256"  , "cmd /c (REG QUERY ""HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v EnableICMPRedirect) 2>&1"
pre_cmd_dic.Add "257"  , "cmd /c (secedit /export /cfg sec.inf /quiet)&(type sec.inf|find ""DisableCAD"")&(del sec.inf) 2>&1"
pre_cmd_dic.Add "258"  , "cmd /c (secedit /export /cfg sec.inf /quiet)&(type sec.inf|find ""ClearPageFileAtShutdown"")&(del sec.inf) 2>&1"
pre_cmd_dic.Add "259"  , "cmd /c (for /F ""usebackq tokens=* delims=*,"" %T in (`""net localgroup|find ""*""""`) do net localgroup ""%T"")&(net users) 2>&1"
pre_cmd_dic.Add "260"  , "cmd /c (net start) 2>&1"
pre_cmd_dic.Add "261"  , "cmd /c (secedit /export /cfg sec.inf /quiet)&(type sec.inf|find ""MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\Machine"")&(type sec.inf|find ""MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\Machine"")&(del sec.inf) 2>&1"
pre_cmd_dic.Add "262"  , "cmd /c (reg query ""HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters"" /v DisableIPSourceRouting|find ""DisableIPSourceRouting"") 2>&1"
pre_cmd_dic.Add "263"  , "cmd /c (reg query ""HKLM\System\CurrentControlSet\Services\Tcpip\Parameters"" /v EnablePMTUDiscovery|find ""EnablePMTUDiscovery"") 2>&1"
pre_cmd_dic.Add "264"  , "cmd /c (reg query ""HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"" /v AutoAdminLogon|find ""AutoAdminLogon"") 2>&1"
pre_cmd_dic.Add "265"  , "cmd /c wmic useraccount where (Disabled=""FALSE"" and LocalAccount=""TRUE"") get name | find /v /i ""name"" | find /i /v /n """"&wmic useraccount where (Disabled=""FALSE"" and LocalAccount=""TRUE"") get name | find /v /i ""name"" | find /i /v /c"""" 2>&1"

pre_keys = pre_cmd_dic.Keys
pre_values = pre_cmd_dic.Items
Dim appendix_cmd_dic
set appendix_cmd_dic = CreateObject("Scripting.Dictionary")
appendix_keys = appendix_cmd_dic.Keys
appendix_values = appendix_cmd_dic.Items

 dim NIC1, Nic, StrIP, localIp
 dim appendix_keys,appendix_values,pre_keys,pre_values,i
 Set NIC1 = getObject("winmgmts:").InstancesOf("Win32_NetworkAdapterConfiguration")
 For Each Nic in NIC1
 if Nic.IPEnabled then
 StrIP = Nic.IPAddress(i)
 if Nic.ServiceName <> "VMnetAdapter" and StrIP <> "0.0.0.0" and InStr(StrIP, "169.254") = 0 then
 localIp = StrIP
 end if
 end if
 next
 
 Dim starttime,curtime
 starttime=Year(Date)&"-"&Month(Date)&"-"&Day(Date)&" "&time
 dim os
 Function OsVersion()
 	set str_result = obj_shell.exec("cmd /c ver")
  str_result.stdin.close
  OsVersion = str_result.stdout.readall
 End Function 
 
Function GetHostName()
    Dim objNTInfo
    Set objNTInfo = CreateObject("WinNTSystemInfo")
    ComputerName = objNTInfo.ComputerName
    GetHostName = ComputerName
End Function
Function replaceCharacter(str)	
	set regEx = New RegExp
		regEx.Pattern ="\x00|\x01|\x02|\x03|\x04|\x05|\x06|\x07|\x08|\x0B|\x0C|\x0E|\x0F|\x10|\x11|\x12|\x13|\x14|\x15|\x16|\x17|\x18|\x19|\x1A|\x1B|\x1C|\x1D|\x1E|\x1F|\x7F"
		regEx.Global = true
		''regEx.test(str)
		replaceCharacter = regEx.Replace(str,"")
End Function

Dim ip_uuid_xml
ip_uuid_xml = localIp & "_" & uuid & "_chk.xml"
Dim oADO 
Dim str_result
Set oADO = CreateObject("ADODB.Stream")
oADO.Charset = "gbk"
oADO.Open
oADO.WriteText "<?xml version=""1.0"" encoding=""GBK""?>" &VbCrLf
oADO.WriteText "<result>" &VbCrLf
oADO.WriteText "<osName><![CDATA["&GetHostName()&"]]></osName>" &VbCrLf

oADO.WriteText "<version><![CDATA["&OsVersion()&"]]></version>" &VbCrLf
oADO.WriteText "<ip><![CDATA["&localIp&"]]></ip>" &VbCrLf
oADO.WriteText "<type><![CDATA[/server/Windows]]></type>" &VbCrLf
oADO.WriteText "<startTime><![CDATA["&starttime&"]]></startTime>"&VbCrLf
oADO.WriteText "<pId><![CDATA[5]]></pId>"&VbCrLf

oADO.WriteText "<scripts>"&VbCrLf
for i=0 to pre_cmd_dic.count -1
    oADO.WriteText "        <script>" &VbCrLf
	oADO.WriteText "			<id>"&pre_keys(i)&"</id>"&VbCrLf
    oADO.WriteText "            <value><![CDATA["
    set str_result = obj_shell.exec(pre_values(i)) 
    str_result.stdin.close 
    if str_result.exitcode = 0 then
            oADO.WriteText replace(replaceCharacter(str_result.stdout.readall), ">", "&gt;") &VbCrLf
    else
            oADO.WriteText "                 failed" &VbCrLf
    end if
    oADO.WriteText "]]></value>" &VbCrLf
    oADO.WriteText "        </script>" &VbCrLf
next
oADO.Writetext "    </scripts>" &VbCrLf

curtime=Year(Date)&"-"&Month(Date)&"-"&Day(Date)&" "&time
oADO.WriteText "<endTime><![CDATA["&curtime&"]]></endTime>"&VbCrLf
Dim fso, Myfile, f2
Set fso = CreateObject("Scripting.FileSystemObject")


if fso.fileexists("c:\apendix.bat") then
    set f2 = fso.getfile("c:\appendix.bat")
    f2.delete
end if
if fso.fileexists("TempWmicBatchFile.bat") then
    set f2 = fso.getfile("TempWmicBatchFile.bat")
    f2.delete
end if
oADO.WriteText "</result>"
oADO.SaveToFile ip_uuid_xml, 2
oADO.close
wscript.echo "DONE ALL"
