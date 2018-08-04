#!env perl
##Author: autoCreated
my $para_num = "2";
my $template_time = "2017-02-07 16:18:01";
#my %para;
@array_basic_flag = ();
@array_pre_flag = ();
@array_appendix_flag = ();

system("if [ ! -d /tmp/secheck ];then mkdir /tmp/secheck; fi");
$pre_description{1} = "是否存在uid=0的违规账户";
$pre_cmd{1} = "cat /etc/passwd |grep -Ev '^#|^\$'| awk -F: '{if(\$3 == 0 && (\$1 != \"root\" && \$1 != \"sfroot\" && \$1 != \"sfdiqu\"))  print \$1}'";
$pre_description{2} = "检查是否限制管理员帐号SSH登录";
$pre_cmd{2} = "cat /etc/ssh/sshd_config|grep -v ^#|grep -i  \"PermitRootLogin\"|awk '{print \$2}'";
$pre_description{3} = "SSH bin 文件是否被替换";
$pre_cmd{3} = "if rpm -Vf /usr/sbin/sshd|grep '/usr/sbin' 1>/dev/null 2>&1;then stat /usr/sbin/sshd;fi";
$pre_description{4} = "检查是否存在ssh olog后门文件";
$pre_cmd{4} = "find / -type f  \\( -name olog -o -name .olog \\)  -ls 2>/dev/null";
$pre_description{5} = "检查是否存在ssh ilog后门文件";
$pre_cmd{5} = "find / -type f  \\( -name ilog -o -name .ilog \\)  -ls 2>/dev/null";
$pre_description{6} = "ls bin 文件是否被替换";
$pre_cmd{6} = "rpm -Vf /bin/ls|grep '/bin/ls'";
$pre_description{7} = "root history是否被删除或替换删除";
$pre_cmd{7} = "find /root -type d -name *bash_history*";
$pre_description{8} = "查看root history";
$pre_cmd{8} = "if [ -f /root/.bash_history ];then 
echo 'yes'
else
echo 'no';fi";
$pre_description{9} = "检查secure日志文件是否被删除";
$pre_cmd{9} = "if [ -f /var/log/secure ]; then 
echo 'yes'
else echo 'no';fi";
$pre_description{10} = "检查messages日志文件是否被删除";
$pre_cmd{10} = "if [ -f /var/log/messages ]; then 
echo 'yes'
else echo 'no';fi";
$pre_description{11} = "查看syslog日志审计服务是否开启";
$pre_cmd{11} = "if [ -f /etc/rsyslog.conf ]; then
service rsyslog status |awk '{print \$NF}'
else
service syslog status|awk '{print \$NF}';fi  ";
$pre_description{12} = "查看非堡垒机的登录";
$pre_cmd{12} = "last -d|grep -v '10.116.216.22'|grep -v '10.116.216.23'|grep -v '10.116.216.24'|grep -v '10.116.216.25'|grep -v '10.116.216.26'|grep -v '10.116.216.27'|grep -v '10.116.216.28'|grep -v '10.116.216.17'|grep -v ^reboot|grep -v '0.0.0.0'|awk '{print \$1,\$3,\$4,\$5,\$6,\$7,\$8,\$9,\$10}'";



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
$xml_string .= '<result uuid= "'.'linux-sec-check-v9'.'" template_time= "2017-02-07 16:18:01'.'">'."\n"; 
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
 
$xml_string .= "\t".'<security type="检查结果">'."\n";                                                                    #基线检查结果展示
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
 $xmlfile = $ip."_"."linuxruqin"."_".$date.".xml";                                                                                                                                                                                                                                                                            
 print $xmlfile."\n";
 open XML,">/tmp/secheck/".$xmlfile or die "Cannot create ip.xml:$!";
 print XML $xml_string;}
 generate_xml();

