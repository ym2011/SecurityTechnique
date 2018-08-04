#!env perl
##Author: autoCreated
my $para_num = "2";
my $template_time = "2016-11-16 11:01:01";
#my %para;
@array_basic_flag = ();
@array_pre_flag = ();
@array_appendix_flag = ();

system("if [ ! -d /tmp/secheck ];then mkdir /tmp/secheck; fi");
$pre_description{1} = "检查是否锁定UID小于500的无用系统帐号";
$pre_cmd{1} = "cat /etc/passwd|awk -F: '{if (\$7==\"/bin/bash\" || \$7==\"/bin/csh\" ) print}'|awk -F: '{if (\$3<500 && \$3!=0) print \$1}'";
$pre_description{2} = "检查口令长度";
$pre_cmd{2} = "cat /etc/login.defs |grep -Ev '^#|^\$'|awk 'BEGIN{IGNORECASE=1}{for(i=1;i<=NF;i++) if(\$i~/PASS_MIN_LEN/) print \$(i+1)}'";
$pre_description{3} = "检查口令复杂度";
$pre_cmd{3} = "cat /etc/pam.d/system-auth|grep -Ev '^#|^\$'|awk  '/pam_cracklib.so/{for(i=1;i<=NF;i++) if(\$i~/minclass=/) print \$i}'|awk -F= '{for(i=1;i<=NF;i++) if(\$i~/minclass/) print \$(i+1)}'";
$pre_description{4} = "检查是否配置用户不能重复使用最近5次（含5次）内已使用的口令";
$pre_cmd{4} = "cat /etc/pam.d/system-auth|grep -Ev '^#|^\$'|awk  '/pam_unix.so/{for(i=1;i<=NF;i++) if(\$i~/remember=/) print \$i}'|awk -F= '{print \$2}'";
$pre_description{5} = "检查是否配置当用户连续认证失败次数超过5次，锁定该用户使用的账号（应用用户除外）";
$pre_cmd{5} = "cat /etc/pam.d/system-auth|grep -Ev '^#|^\$'|awk  '/pam_tally2.so/{for(i=1;i<=NF;i++) if(\$i~/deny=/) print \$i}'|awk -F= '{print \$2}'";
$pre_description{6} = "检查是否配置ssh认证密码策略";
$pre_cmd{6} = "cat /etc/pam.d/sshd|grep -c 'system-auth'";
$pre_description{7} = "检查是否配置认证使用system-auth";
$pre_cmd{7} = "cat /etc/pam.d/login|grep -c 'system-auth'";
$pre_description{8} = "检查是否存在uid为0的违规账户";
$pre_cmd{8} = "cat /etc/passwd |grep -Ev '^#|^\$'| awk -F: '{if(\$3 == 0 && (\$1 != \"root\" && \$1 != \"sfroot\" && \$1 != \"sfdiqu\"))  print \$1}'";
$pre_description{9} = "检查是否禁用rhosts方式登陆验证";
$pre_cmd{9} = "find /etc/pam.d  -type f -name \"*\" | xargs grep \"rhosts_auth\"|awk -F: '{print \$1}'";
$pre_description{10} = "检查是否设置at白名单";
$pre_cmd{10} = "locate at.deny 2>/dev/null|wc -l";
$pre_description{11} = "检查是否设置cron白名单";
$pre_cmd{11} = "locate cron.deny 2>/dev/null|wc -l";
$pre_description{12} = "检查是否设置at/cron白名单，限制只有root用户、及应用用户（mwopr、数据库用户）可以执行at";
$pre_cmd{12} = "cat /etc/at.allow 2>/dev/null|grep -v 'root'|grep -v  'mwopr'|grep -v 'oracle'|grep -v 'mysql'|grep -v 'grid'";
$pre_description{13} = "检查是否设置at/cron白名单，限制只有root用户、及应用用户（mwopr、数据库用户）可以执行cron";
$pre_cmd{13} = "cat /etc/cron.allow 2>/dev/null|grep -v 'root'|grep -v  'mwopr'|grep -v 'oracle'|grep -v 'mysql'|grep -v 'grid'";
$pre_description{14} = "检查是否限制管理员帐号Telnet登录";
$pre_cmd{14} = "cat /etc/pam.d/login|grep -Ev '^#|^\$'|awk '/pam_securetty.so/{if(\$1~/^auth/) print \$NF}'";
$pre_description{15} = "检查是否限制管理员帐号SSH登录";
$pre_cmd{15} = "cat /etc/ssh/sshd_config|grep -v ^#|grep -i  \"PermitRootLogin no\"|head -1";
$pre_description{16} = "检查是否限制管理员帐号SSH登录";
$pre_cmd{16} = "cat /etc/securetty|grep  \"pts\"";
$pre_description{17} = "检查用户主目录权限";
$pre_cmd{17} = "find /home   \\( -perm -0755 -o -perm -0777 \\)  -maxdepth 1 -print 2>/dev/null|awk -F/ '{if(\$3 != \"\") print}'";
$pre_description{18} = "检查password文件权限";
$pre_cmd{18} = "ls -al /etc/passwd|awk '{print \$1}'";
$pre_description{19} = "检查shadow文件权限";
$pre_cmd{19} = "ls -al /etc/shadow|awk '{print \$1}'";
$pre_description{20} = "检查group文件权限";
$pre_cmd{20} = "ls -al /etc/group|awk '{print \$1}'";
$pre_description{21} = "检查gshadow文件权限";
$pre_cmd{21} = "ls -al /etc/gshadow|awk '{print \$1}'";
$pre_description{22} = "检查用户目录/文件的缺省访问权限配置";
$pre_cmd{22} = "cat /etc/profile |grep -Ev '^#|^\$'|awk '{IGNORECASE=1}{for(i=1;i<=NF;i++) if(\$i~/UMASK/) print \$(i+1)}'|awk 'END{print}'";
$pre_description{23} = "检查用户主目录的缺省访问权限配置";
$pre_cmd{23} = "cat /etc/login.defs|grep -Ev '^#|^\$'|awk 'BEGIN{IGNORECASE=1}{for(i=1;i<=NF;i++) if(\$i~/UMASK/) print \$(i+1)}'";
$pre_description{24} = "检查是否设置超时自动退出";
$pre_cmd{24} = "cat /etc/profile | grep -Ev '^#|^\$' | grep -i \"TMOUT[[:space:]]*=[[:space:]]*[0-9]*\"|awk -F= '{print \$2}'";
$pre_description{25} = "检查是否设置超时自动退出";
$pre_cmd{25} = "cat /etc/profile | grep -Ev '^#|^\$'| awk  '/^export/{if(\$2~/TMOUT/) print \"yes\"}'";
$pre_description{26} = "检查是否配置记录全局用户的操作日志";
$pre_cmd{26} = "cat /etc/bashrc|grep -Ev '^#|^\$'|awk 'BEGIN{IGNORECASE=1}{for(i=1;i<=NF;i++) if(\$i~/export/) print \$(i+1)}'";
$pre_description{27} = "检查是否配置用户操作日志写入syslog";
$pre_cmd{27} = "if [ -f /etc/rsyslog.conf ]; then
cat /etc/rsyslog.conf|grep -Ev '^#|^\$'|awk   '{if(\$1~/^local6/) print \$2}'|head -1
else
cat /etc/syslog.conf 2>/dev/null|grep -Ev '^#|^\$'|awk   '{if(\$1~/^local6/) print \$2}'|head -1;fi  ";
$pre_description{28} = "检查是否配置系统安全日志记录";
$pre_cmd{28} = "if [ -f /etc/rsyslog.conf ]; then
cat /etc/rsyslog.conf|grep -Ev '^#|^\$'|awk   '{if(\$1~/^authpriv/) print \$2}'|awk -F'/'  '{print \$4}'
else
cat /etc/syslog.conf 2>/dev/null|grep -Ev '^#|^\$'|awk   '{if(\$1~/^authpriv/) print \$2}'|awk -F'/'  '{print \$4}';fi";
$pre_description{29} = "检查是否配置系统记录cron日志";
$pre_cmd{29} = "if [ -f /etc/rsyslog.conf ]; then
cat /etc/rsyslog.conf|grep -Ev '^#|^\$'|awk   '{if(\$1~/^cron/) print \$2}'|awk -F'/'  '{print \$4}'
else
cat /etc/syslog.conf 2>/dev/null|grep -Ev '^#|^\$'|awk   '{if(\$1~/^cron/) print \$2}'|awk -F'/'  '{print \$4}';fi";
$pre_description{30} = "检查secure日志文件权限";
$pre_cmd{30} = "ls -al /var/log/secure|awk '{print \$1}'";
$pre_description{31} = "检查cron日志文件权限";
$pre_cmd{31} = "ls -al /var/log/cron|awk '{print \$1}'";
$pre_description{32} = "检查messages日志文件权限";
$pre_cmd{32} = "ls -al /var/log/messages|awk '{print \$1}'";
$pre_description{33} = "检查是否设置Telnet开机启动";
$pre_cmd{33} = "chkconfig --list 2>/dev/null| grep '3:on'|grep -c \"klogin\"";
$pre_description{34} = "检查Telnet服务是否正在运行";
$pre_cmd{34} = "netstat -tuln|awk 'BEGIN{IGNORECASE=1}/listen/{if(\$4==\"0.0.0.0:23\")print \"no\"}'" ;
$pre_description{35} = "检查是否设置sendmail开机启动";
$pre_cmd{35} = "chkconfig --list 2>/dev/null| grep '3:on'|grep -c \"sendmail\"";
$pre_description{36} = "检查sendmail服务是否正在运行";
$pre_cmd{36} = "netstat -tuln|awk 'BEGIN{IGNORECASE=1}/listen/{if(\$4==\"0.0.0.0:25\")print \"no\"}'";
$pre_description{37} = "检查是否设置ftp开机启动";
$pre_cmd{37} = "chkconfig --list 2>/dev/null| grep '3:on'|grep -c \"ftp\"";
$pre_description{38} = "检查ftp服务是否正在运行";
$pre_cmd{38} = "netstat -tuln|awk 'BEGIN{IGNORECASE=1}/listen/{if(\$4==\"0.0.0.0:21\")print \"no\"}'";
$pre_description{39} = "检查snmp服务是否开启";
$pre_cmd{39} = "netstat -tuln|awk 'BEGIN{IGNORECASE=1}/listen/{if(\$4==\"0.0.0.0:161\")print \"no\"}' ";
$pre_description{40} = "检查snmp服务是否设置开机启动";
$pre_cmd{40} = "chkconfig --list|grep '3:on'|grep -c \"snmpd\"";
$pre_description{41} = "检查NTP服务是否正在运行";
$pre_cmd{41} = "ps -ef|grep -E 'ntpd|ntp'|grep -c ^'ntp'";
$pre_description{42} = "检查是否配置时钟同步服务器";
$pre_cmd{42} = "cat /etc/ntp.conf  2>/dev/null|grep -Ev '^#|^\$'| awk  '{for(i=1;i<=NF;i++) if(\$i~/server/) print }'|awk  '{for(i=1;i<=NF;i++) if(\$i~/true/) print \$(i-1)}'";
$pre_description{43} = "禁止终端用户使用Ctrl+Alt+Delete重启主机";
$pre_cmd{43} = "if [ -f /etc/init/control-alt-delete.conf ]; then
cat /etc/init/control-alt-delete.conf  2>/dev/null|grep ^#|grep  -c 'shutdown'
else
cat /etc/inittab 2>/dev/null|grep ^#|grep -c '/sbin/shutdown';fi";

$pre_basic{1} = "uname -a|awk '{print \$1}'";
$pre_basic{2} = "cat /etc/redhat-release";
$pre_basic{3} = "uname -a|awk '{print \$3}'";
$pre_basic{4} = "uname -a|awk '{print \$2}'";
$pre_basic{5} = "ifconfig -a|grep inet|grep -v 127.0.0.1|grep -v inet6|head -n 1|awk '{print \$2}'|tr -d \"addr:\"";

$pre_basic_description{1} = "系统名称";
$pre_basic_description{2} = "系统版本";
$pre_basic_description{3} = "系统内核版本";
$pre_basic_description{4} = "主机名";
$pre_basic_description{5} = "Ip地址";


push(@array_pre_flag, 1);
push(@array_pre_flag, 2);
push(@array_pre_flag, 3);
push(@array_pre_flag, 4);
push(@array_pre_flag, 5);
push(@array_pre_flag, 6);
push(@array_pre_flag, 7);
push(@array_pre_flag, 8);
push(@array_pre_flag, 9);
push(@array_pre_flag, 10);
push(@array_pre_flag, 11);
push(@array_pre_flag, 12);
push(@array_pre_flag, 13);
push(@array_pre_flag, 14);
push(@array_pre_flag, 15);
push(@array_pre_flag, 16);
push(@array_pre_flag, 17);
push(@array_pre_flag, 18);
push(@array_pre_flag, 19);
push(@array_pre_flag, 20);
push(@array_pre_flag, 21);
push(@array_pre_flag, 22);
push(@array_pre_flag, 23);
push(@array_pre_flag, 24);
push(@array_pre_flag, 25);
push(@array_pre_flag, 26);
push(@array_pre_flag, 27);
push(@array_pre_flag, 28);
push(@array_pre_flag, 29);
push(@array_pre_flag, 30);
push(@array_pre_flag, 31);
push(@array_pre_flag, 32);
push(@array_pre_flag, 33);
push(@array_pre_flag, 34);
push(@array_pre_flag, 35);
push(@array_pre_flag, 36);
push(@array_pre_flag, 37);
push(@array_pre_flag, 38);
push(@array_pre_flag, 39);
push(@array_pre_flag, 40);
push(@array_pre_flag, 41);
push(@array_pre_flag, 43);
push(@array_pre_flag, 43);

push(@array_basic_flag, 1);
push(@array_basic_flag, 2);
push(@array_basic_flag, 3);
push(@array_basic_flag, 4);
push(@array_basic_flag, 5);



sub get_os_info{
 my %os_info = (
 "hostname"=>"","osname"=>"","osversion"=>"");
 $os_info{"hostname"} = `uname -n`;
 $os_info{"osname"} = `uname -s`;
 $os_info{"osversion"} = `uname -r`;
foreach (%os_info){   chomp;}
return %os_info;}

sub add_item{
my $date = `date +%Y-%m-%d`;
chomp $date; 
my ($string, $flag, $command, $value)= @_;
 $string .= "\t\t".'<item flag="'.$flag.'">'."\n";
 $string .= "\t\t\t".'<cmd info="'.$date.'">'."\n";
 $string .= "\t\t\t".'<check_description>"'. $pre_description{$key} .'"</check_description>'."\n";
 $string .= "\t\t\t<command><![CDATA[".$command."]]></command>\n";
 $string .= "\t\t\t<value><![CDATA[".$value."]]></value>\n";
 $string .= "\t\t\t</cmd>\n";
 $string .= "\t\t</item>\n";
return $string;}

sub generate_xml{
my %os_info = get_os_info();
my $host_name = $os_info{"hostname"};
my $date = `date +%Y-%m-%d`;
chomp $date;
my $xml_string = "";
$xml_string .='<?xml version="1.0" encoding="UTF-8"?>'."\n";                                                                 #基础信息展示
$xml_string .= '<result uuid= "'.'linux-sec-check-v9'.'" template_time= "2016-11-01 11:01:01'.'">'."\n"; 
foreach $key (@array_basic_flag){
$value = $pre_basic{$key};
my $tmp_result = `$value`;
chomp $tmp_result;
$tmp_result =~ s/>/&gt;/g;
$xml_string .= "\t".'<basic_information>'."\n";
$xml_string .= "\t\t".'<cmd info="'.$date.'">';
$xml_string .= '</cmd>'."\n";
$xml_string .= "\t\t\t".'<description>"'.$pre_basic_description{$key}.'"</description>'."\n";
$xml_string .= "\t\t\t<command><![CDATA[".$pre_basic{$key}." ]]></command>\n";
$xml_string .= "\t\t\t<value><![CDATA[".$tmp_result."]]></value>\n";
$xml_string .= "\t</basic_information>\n";}
 
$xml_string .= "\t".'<security type="基线检查结果">'."\n";                                                                    #基线检查结果展示
foreach $key (@array_pre_flag){
 $value = $pre_cmd{$key};
 my $tmp_result = `$value`;
 chomp $tmp_result;
 $tmp_result =~ s/>/&gt;/g;
 $xml_string = &add_item( $xml_string, $key, $value, $tmp_result );}
 $xml_string .= "\t</security>\n";
 
 $xml_string .= "\t".'<security type="附加内容">'."\n";                                                                       #附加信息展示
 foreach $key (@array_appendix_flag){
 $value = $appendix_cmd{$key};
 my $tmp_result = `$value`;
 chomp $tmp_result;
 $tmp_result =~ s/>/&gt;/g;
 $xml_string = &add_item( $xml_string, $key, $value, $tmp_result );}
 $xml_string .= "\t"."</security>"."\n";
 $xml_string .= "</result>"."\n";
 
my $ipaddr = $pre_basic{5};
$ip = `$ipaddr`;
chomp $ip;
 $xmlfile = $ip."_"."linux-sec-check"."_".$date.".xml";                                                                                                                                                                                                                                                                            
 print $xmlfile."\n";
 open XML,">/tmp/secheck/".$xmlfile or die "Cannot create ip.xml:$!";
 print XML $xml_string;}
 generate_xml();

