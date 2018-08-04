#!env perl
#Author: autoCreated
my $para_num = "1";
my %para;
@array_pre_flag = ();
@array_appendix_flag = ();

$para{Linux_su_password} = $ARGV[1];
$para{Linux_su_user} = $ARGV[2];

$pre_cmd{1} = "if ([ -f /etc/redhat-release ] && [ -f /etc/pam.d/system-auth ]);
then FILE=/etc/pam.d/system-auth
cat \$FILE |sed '/^#/d'|sed '/^\$/d'|egrep -i \"auth[[:space:]]*required[[:space:]]*pam_tally.so|auth[[:space:]]*required[[:space:]]*pam_tally2.so|account[[:space:]]*required[[:space:]]*pam_tally.so|account[[:space:]]*required[[:space:]]*pam_tally2.so\"
fi
suse_version=`cat /etc/SuSE-release 2>/dev/null|grep -i \"VERSION\"|awk '{print \$3}'`
if ([ \"x\$suse_version\" = x10 ] || [ \"x\$suse_version\" = x11 ])
then
FILE=/etc/pam.d/common-password
cat \$FILE|grep -v '^#'|egrep -i \"auth[[:space:]]*required[[:space:]]*pam_tally.so|auth[[:space:]]*required[[:space:]]*pam_tally2.so|account[[:space:]]*required[[:space:]]*pam_tally.so|account[[:space:]]*required[[:space:]]*pam_tally2.so\"
else
if [ -f /etc/SuSE-release ]
then
FILE=/etc/pam.d/passwd
cat \$FILE|grep -v '^#'|egrep -i \"auth[[:space:]]*required[[:space:]]*pam_tally.so|auth[[:space:]]*required[[:space:]]*pam_tally2.so|account[[:space:]]*required[[:space:]]*pam_tally.so|account[[:space:]]*required[[:space:]]*pam_tally2.so\"
fi
fi
unset suse_version FILE;
";
push(@array_pre_flag, 1);$pre_cmd{2} = "for  PART  in `grep -v ^# /etc/fstab | awk '(\$6 != \"0\") {print \$2 }'`
do
find \$PART -type f \\( -perm -04000 -o -perm -02000 \\)  -xdev -exec ls -lg {} \\; 2>/dev/null
done
";
push(@array_pre_flag, 2);$pre_cmd{3} = "cat /etc/profile |grep -v \"^[[:space:]]*#\"|grep -v \"^\$\"|grep \"TMOUT\"
";
push(@array_pre_flag, 3);$pre_cmd{4} = "if grep -v \"^[[:space:]]*#\" /etc/ssh/sshd_config|grep -i \"PermitRootLogin no\"
then echo \"This device does not permit root to ssh login,check result:true\";
else
echo \"This device permits root to ssh login,check result:false\";
fi
if grep  -v \"^[[:space:]]*#\" /etc/ssh/sshd_config|egrep \"^protocol[[:space:]]*2|^Protocol[[:space:]]*2\"
then echo \"SSH protocol version is 2,check result:true\"
else
echo \"SSH protocol version is not 2,check result:false\"
fi
";
push(@array_pre_flag, 4);$pre_cmd{5} = "chkconfig --list |egrep \"telnet|ssh\"
ps -ef|grep \"sshd\"|grep -v \"grep\"
echo \"telnet_status=\"`chkconfig --list |egrep \"[[:space:]]telnet\"|grep \"on\"|wc -l`
echo \"ssh_status=\"`ps -ef|grep \"sshd\"|grep -v \"grep\"|wc -l`
unset telnet_status ssh_status
";
push(@array_pre_flag, 5);$pre_cmd{6} = "find / -maxdepth 3 -name .netrc 2>/dev/null
find / -maxdepth 3 -name .rhosts 2>/dev/null
find / -maxdepth 3 -name hosts.equiv 2>/dev/null
echo \"totalNum_netrc=\"`find / -maxdepth 3 -name .netrc 2>/dev/null|wc -l`
echo \"totalNum_rhosts=\"`find / -maxdepth 3 -name .rhosts 2>/dev/null|wc -l`
echo \"totalNum_hosts.equiv=\"`find / -maxdepth 3 -name hosts.equiv 2>/dev/null|wc -l`
";
push(@array_pre_flag, 6);$pre_cmd{7} = "awk '{print \$1\":\"\$2}' /etc/profile|grep -v \"^[[:space:]]*#\"|grep -i umask|tail -n1
";
push(@array_pre_flag, 7);$pre_cmd{8} = "ls -alL /etc/passwd /etc/shadow /etc/group
echo \"passwd_total=\"`ls -alL /etc/passwd 2>/dev/null|grep -v  \"[r-][w-]-[r-]--[r-]--\"|grep \"[r-][w-][x-][r-][w-][x-][r-][w-][x-]\"|wc -l`
echo \"shadow_total=\"`ls -alL /etc/shadow 2>/dev/null|grep -v  \"[r-]--------\"|grep \"[r-][w-][x-][r-][w-][x-][r-][w-][x-]\"|wc -l`
echo \"group_total=\"`ls -alL /etc/group 2>/dev/null|grep -v  \"[r-][w-]-[r-]--[r-]--\"|grep \"[r-][w-][x-][r-][w-][x-][r-][w-][x-]\"|wc -l`
";
push(@array_pre_flag, 8);$pre_cmd{9} = "cat /etc/login.defs |grep -v \"^[[:space:]]*#\"|grep -E '^\\s*PASS_MAX_DAYS|^\\s*PASS_MIN_DAYS|^\\s*PASS_WARN_AGE'
";
push(@array_pre_flag, 9);$pre_cmd{10} = "awk -F: '(\$3 == 0) { print \$1 }' /etc/passwd
echo \"result=\"`awk -F: '(\$3 == 0) { print \$1 }' /etc/passwd | grep -v \"^[[:space:]]*#\" |grep -v root|wc -l`
";
push(@array_pre_flag, 10);$pre_cmd{11} = "Calculate ()
{
DCREDIT=`cat \$FILE|egrep -v \"^#|^\$\"|grep -w \"dcredit\"|sed 's/^.*dcredit=//g'|sed 's/\\s.*\$//g'`;
LCREDIT=`cat \$FILE|egrep -v \"^#|^\$\"|grep -w \"lcredit\"|sed 's/^.*lcredit=//g'|sed 's/\\s.*\$//g'`;
UCREDIT=`cat \$FILE|egrep -v \"^#|^\$\"|grep -w \"ucredit\"|sed 's/^.*ucredit=//g'|sed 's/\\s.*\$//g'`;
OCREDIT=`cat \$FILE|egrep -v \"^#|^\$\"|grep -w \"ocredit\"|sed 's/^.*ocredit=//g'|sed 's/\\s.*\$//g'`;
MINLEN=`cat \$FILE|grep -v \"^#|^\$\"|grep \"minlen\"|sed 's/^.*minlen=//g'|sed 's/\\s.*\$//g'`;
echo \"DCREDIT=\$DCREDIT\";
echo \"LCREDIT=\$LCREDIT\";
echo \"UCREDIT=\$UCREDIT\";
echo \"OCREDIT=\$OCREDIT\";
echo \"MINCLASS=\$MINLEN\";
unset DCREDIT LCREDIT UCREDIT OCREDIT MINLEN;
}
if ([ -f /etc/redhat-release ] && [ -f /etc/pam.d/system-auth ]);
then
FILE=/etc/pam.d/system-auth;
Calculate;
fi
suse_version=`cat /etc/SuSE-release 2>/dev/null|grep -i \"VERSION\"|awk '{print \$3}'`
if ([ \"x\$suse_version\" = x10 ] || [ \"x\$suse_version\" = x11 ])
then
FILE=/etc/pam.d/common-password
Calculate;
else
if [ -f /etc/SuSE-release ]
then
FILE=/etc/pam.d/passwd
Calculate;
fi
fi
unset FILE suse_version;
";
push(@array_pre_flag, 11);$pre_cmd{12} = "echo \$PATH
echo \"result=`echo \$PATH|egrep \"^\\.\\:|^\\.\\.\\:|\\:\\.\$|\\:\\.\\.\$|\\:\\.\\:|\\:\\.\\.\\:\"|wc -l`\"
";
push(@array_pre_flag, 12);$pre_cmd{13} = "for PART in `grep -v ^# /etc/fstab | awk '(\$6 != \"0\") {print \$2 }'`
do
find \$PART -xdev -type d \\( -perm -0002 -a ! -perm -1000 \\) -xdev -exec ls -ld {} \\; 2>/dev/null;
done
";
push(@array_pre_flag, 13);$pre_cmd{14} = "for PART in `grep -v ^# /etc/fstab | awk '(\$6 != \"0\") {print \$2 }'`
do
find \$PART -xdev -type f \\( -perm -0002 -a ! -perm -1000 \\) -xdev -exec ls -ld {} \\; 2>/dev/null;
done
";
push(@array_pre_flag, 14);$pre_cmd{15} = "for PART in `grep -v ^# /etc/fstab | awk '(\$6 != \"0\") {print \$2 }'`
do
find \$PART -nouser -o -nogroup -print 2>/dev/null
done
";
push(@array_pre_flag, 15);$pre_cmd{16} = "chkconfig --list |egrep \"telnet\"
telnet_status=`chkconfig --list|egrep \"telnet.*\"|egrep \"on|启用\"|wc -l`
if [ \$telnet_status -ge 1 ]
then
echo \"pts_count=\"`cat /etc/securetty|grep -v \"^[[:space:]]*#\"|grep \"pts/*\"|wc -l`
else
echo \"Telnet process is not open\"
fi
unset telnet_status
";
push(@array_pre_flag, 16);$pre_cmd{17} = "cat /etc/profile|grep -v \"^[[:space:]]*#\"|grep \"ulimit[[:space:]]*-S[[:space:]]*-c[[:space:]]*0[[:space:]]*>[[:space:]]*/dev/null[[:space:]]*2>&1\"
cat /etc/security/limits.conf|grep -v \"[[:space:]]*#\"
";
push(@array_pre_flag, 17);$pre_cmd{18} = "if [ -f /etc/syslog.conf ];
then
cat /etc/syslog.conf | grep -v \"^[[:space:]]*#\" | grep -E '[[:space:]]*.+@.+';
fi;
if [ -s /etc/syslog-ng/syslog-ng.conf ];
then
ret_1=`cat /etc/syslog-ng/syslog-ng.conf | grep -v \"^[[:space:]]*#\" | grep \"port(514)\"|awk '{print \$2}'`;
if [ -n \"\$ret_1\" ];
then
ret_2=`cat /etc/syslog-ng/syslog-ng.conf | grep -v \"^[[:space:]]*#\" | grep \"destination(\$ret_1)\"`;
if [ -n \"\$ret_2\" ];
then
echo \"Set the log server:true\";
else
echo \"not Set the log server:false\";
fi;
fi;
fi;
if [ -f /etc/rsyslog.conf ];
then cat /etc/rsyslog.conf | grep -v \"^[[:space:]]*#\" | grep -E '[[:space:]]*.+@.+';
fi
";
push(@array_pre_flag, 18);$pre_cmd{19} = "ssh_status=`ps -ef|grep \"sshd\"|grep -v \"grep\"|wc -l`;
if ([ \$ssh_status != 0 ] && [ -s /etc/motd ]);
then
echo \"sshd is running,banner is not null,check result:true\";
else
if [ \$ssh_status -ge 1 ];
then
echo \"sshd is running,banner is null,check result:false\";
else
if [ -s /etc/motd ];
then
echo \"sshd is not running,banner is not null,check result:true\";
else
echo \"sshd is not running,banner is null,check result:true\";
fi;
fi;
fi;
unset ssh_status;
";
push(@array_pre_flag, 19);$pre_cmd{20} = "egrep \"^lp:|^sync:|^halt:|^news:|^uucp:|^operator:|^games:|^gopher:|^smmsp:|^nfsnobody:|^nobody:\" /etc/shadow|awk -F: '(\$2!~/\\*LK\\*/) {print \$1\":\"\$2}'
egrep \"^lp:|^sync:|^halt:|^news:|^uucp:|^operator:|^games:|^gopher:|^smmsp:|^nfsnobody:|^nobody:\" /etc/passwd|awk -F: '(\$7!~/bin\\/false/) {print \$1\":\"\$7}'
echo \"result_LK=\"`egrep \"^lp:|^sync:|^halt:|^news:|^uucp:|^operator:|^games:|^gopher:|^smmsp:|^nfsnobody:|^nobody:\" /etc/shadow|awk -F: '(\$2!~/\\*LK\\*/) {print \$1\":\"\$2}'|wc -l`
echo \"result_shell=\"`egrep \"^lp:|^sync:|^halt:|^news:|^uucp:|^operator:|^games:|^gopher:|^smmsp:|^nfsnobody:|^nobody:\" /etc/passwd|awk -F: '(\$7!~/bin\\/false/) {print \$1\":\"\$7}'|wc -l`
";
push(@array_pre_flag, 20);$pre_cmd{21} = "ls -lL /etc/passwd 2>/dev/null
echo \"passwd=\"`ls -lL /etc/passwd 2>/dev/null|grep -v \"[r-][w-]-[r-]--[r-]--\"|wc -l`
ls -lL /etc/group 2>/dev/null
echo \"group=\"`ls -lL /etc/group 2>/dev/null|grep -v \"[r-][w-]-[r-]--[r-]--\"|wc -l`
ls -lL /etc/services 2>/dev/null
echo \"services=\"`ls -lL /etc/services 2>/dev/null|grep -v \"[r-][w-]-[r-]--[r-]--\"|wc -l`
ls -lL /etc/shadow 2>/dev/null
echo \"shadow=\"`ls -lL /etc/shadow 2>/dev/null|grep -v \"[r-]--------\"|wc -l`
ls -lL /etc/xinetd.conf 2>/dev/null
echo \"xinetd=\"`ls -lL /etc/xinetd.conf 2>/dev/null|grep -v \"[r-][w-]-------\"|wc -l`
ls -lLd /etc/security 2>/dev/null
echo \"security=\"`ls -lLd /etc/security 2>/dev/null|grep -v \"[r-][w-]-------\"|wc -l`
";
push(@array_pre_flag, 21);$pre_cmd{22} = "if [ -f /etc/syslog.conf ];
then
syslog=`cat /etc/syslog.conf | grep -v \"^[[:space:]]*#\" | grep \"*.err\\;kern\\.debug\\;daemon\\.notice[[:space:]]*/var/adm/messages\"|wc -l`;
if [ \$syslog -ge 1 ];
then
echo \"syslog check result:true\";
else
echo \"syslog check result:false\";
fi;
fi;
if [ -f /etc/rsyslog.conf ];
then
rsyslog=`cat /etc/rsyslog.conf | grep -v \"^[[:space:]]*#\" | grep \"*.err\\;kern\\.debug\\;daemon\\.notice[[:space:]]*/var/adm/messages\"|wc -l`;
if [ \$rsyslog -ge 1 ];
then
echo \"rsyslog check result:true\";
else
echo \"rsyslog check result:false\";
fi;
fi;
if [ -s /etc/syslog-ng/syslog-ng.conf ];
then suse_ret=`cat /etc/syslog-ng/syslog-ng.conf | grep -v \"^[[:space:]]*#\" | grep \"level(err) or facility(kern) and level(debug) or facility(daemon) and level(notice)\"`;
if [ -n \"\$suse_ret\" ];
then suse_ret2=`cat /etc/syslog-ng/syslog-ng.conf | grep -v \"^[[:space:]]*#\" | grep 'file(\"/var/adm/msgs\")'`;
if [ -n \"\$suse_ret2\" ];
then suse_ret3=`cat /etc/syslog-ng/syslog-ng.conf | grep -v \"^[[:space:]]*#\" | grep \"destination(msgs)\"`;
fi;
fi;
fi;
if [ -n \"\$suse_ret3\" ];
then echo \"suse:valid\";
else echo \"suse:no value\";
fi;
unset suse_ret suse_ret2 suse_ret3 rsyslog syslog;
";
push(@array_pre_flag, 22);$pre_cmd{23} = "UP_GIDMIN=`(grep -v ^# /etc/login.defs |grep \"^GID_MIN\"|awk '(\$1=\"GID_MIN\") {print \$2}')`
UP_GIDMAX=`(grep -v ^# /etc/login.defs |grep \"^GID_MAX\"|awk '(\$1=\"GID_MAX\") {print \$2}')`
egrep -v \"oracle|sybase|postgres\" /etc/passwd|awk -F: '(\$4>='\$UP_GIDMIN' && \$4<='\$UP_GIDMAX') {print \$1\":\"\$3\":\"\$4}'
echo \$UP_GIDMIN \$UP_GIDMAX
echo \"result=\"`egrep -v \"oracle|sybase|postgres\" /etc/passwd|awk -F: '(\$4>='\$UP_GIDMIN' && \$4<='\$UP_GIDMAX') {print \$1\":\"\$3\":\"\$4}'|wc -l`
unset UP_GIDMIN UP_GIDMAX
";
push(@array_pre_flag, 23);$pre_cmd{24} = "ssh_banner=`cat /etc/ssh/sshd_config | grep -v '^[[:space:]]*#' | grep -i Banner|awk '{print \$2}'`;
ssh_status=`netstat -antp|grep -i listen|grep \":22\\>\"|wc -l`;
if ([ \"\$ssh_status\" != 0 ] && [ -s \"\$ssh_banner\" ]);
then
echo \"sshd is running.sshd banner is not null.sshd banner check result:true\";
else
if [ \"\$ssh_status\" != 0 ];
then
echo \"sshd is running.sshd banner is null.sshd banner check result:false\";
else
echo \"sshd is not running.sshd banner check result:true\";
fi;
fi;
unset ssh_banner ssh_status;
";
push(@array_pre_flag, 24);$pre_cmd{25} = "echo \"ip_forward=\"`sysctl -n net.ipv4.ip_forward`
";
push(@array_pre_flag, 25);$pre_cmd{26} = "ps -ef |egrep \"nfs|rpc.mountd|rpc.nfsd|rpc.lockd|rpc.statd\"|egrep -v \"egrep|grep\"|grep -v kblockd
NFSSTATUS=`ps -ef |egrep \"nfs|rpc.mountd|rpc.nfsd|rpc.lockd|rpc.statd\"|egrep -v \"egrep|grep\"|grep -v kblockd|wc -l`
NFSAllowNo=`egrep -i \"nfs\" /etc/hosts.allow |sed '/^#/d'|sed '/^\$/d'|wc -l`
NFSDenyNo=`egrep -i \"nfs:all|all:all\" /etc/hosts.deny |sed '/^#/d'|sed '/^\$/d'|wc -l`
if [ \$NFSSTATUS = 0 ];
then
echo \"NFS daemon not running\";
else
if ([ \$NFSAllowNo != 0 ] && [ \$NFSDenyNo != 0 ])
then
echo \"NFS daemon running.check resule:true\";
else
echo \"NFS daemon running.check result:false\";
fi;
fi;
unset NFSSTATUS NFSAllowNo;
";
push(@array_pre_flag, 26);$pre_cmd{27} = "cat /etc/inittab|grep -v \"^#\"|grep \"ctrlaltdel\"
";
push(@array_pre_flag, 27);$pre_cmd{28} = "cat /etc/hosts.allow |sed '/^#/d'|sed '/^\$/d'|egrep -i \"sshd|telnet|all\"
cat /etc/hosts.deny |sed '/^#/d'|sed '/^\$/d'|egrep -i \"all:all\"
echo \"allowno=\"`egrep -i \"sshd|telnet|all\" /etc/hosts.allow |sed '/^#/d'|sed '/^\$/d'|wc -l`
echo \"denyno=\"`egrep -i \"sshd|telnet|all\" /etc/hosts.deny |sed '/^#/d'|sed '/^\$/d'|wc -l`
";
push(@array_pre_flag, 28);$pre_cmd{29} = "awk -F: '( \$2 == \"\" ) { print \$1 }' /etc/shadow
echo \"result=\"`awk -F: '( \$2 == \"\" ) { print \$1 }' /etc/shadow |wc -l`
";
push(@array_pre_flag, 29);$pre_cmd{30} = "ntpstatus=`ps -ef|egrep \"ntp|ntpd\"|grep -v grep|wc -l`
if [ \$ntpstatus != 0 ];
then
echo \"ntp:start\"
grep \"^server\" /etc/ntp.conf|grep -v \"127.127.1.0\"|grep -v \"127.0.0.1\";
echo \"ntpserverno=\"`grep \"^server\" /etc/ntp.conf|grep -v \"127.127.1.0\"|grep -v \"127.0.0.1\"|wc -l`;
else
echo \"ntp:stop\"
crontab -l|grep -v \"^#\"|grep ntp;
echo \"ntpserverno=\"`crontab -l|grep -v \"^#\"|grep ntp|wc -l`;
fi
unset ntpstatus ntpserverno;
";
push(@array_pre_flag, 30);$pre_cmd{31} = "echo \"accept_redirects=\"`sysctl -n net.ipv4.conf.all.accept_redirects`
";
push(@array_pre_flag, 31);$pre_cmd{32} = "FTPSTATUS=`ps -ef|grep ftpd|grep -v grep|wc -l`
Check_ftp ()
{
if [ -f /etc/vsftpd.conf ];
then
FTPCONF=\"/etc/vsftpd.conf\";
else
if [ -f /etc/vsftpd/vsftpd.conf ];
then
FTPCONF=\"/etc/vsftpd/vsftpd.conf\";
fi;
fi;
if [ -f \"\$FTPCONF\" ]
then
if [ `grep -v \"^[[:space:]]*#\" \$FTPCONF|grep -i \"ftpd_banner\"|wc -l` -ne 0 ];
then
echo \"vsftpd is running.Banner in \$FTPCONF is recommended.FTP check result:true\";
else
echo \"vsftpd is running.Banner in \$FTPCONF is not recommended.FTP check result:false\";
fi;
fi;
if [ -f /etc/pure-ftpd/pure-ftpd.conf ];
then
if [ `cat /etc/pure-ftpd/pure-ftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"FortunesFile\"|wc -l` -eq 0 ]
then
echo \"pure-ftpd is running.banner in pure-ftpd.conf is not recommended.FTP check result:false.\";
else
if [ -s \"`cat /etc/pure-ftpd/pure-ftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"FortunesFile\"|awk '{print \$2}'`\" ];
then
echo \"pure-ftpd is running.Banner in pure-ftpd.conf is recommended.FTP check result:true.\";
else
echo \"pure-ftpd is running.Banner in pure-ftpd.conf is not recommended.FTP check result:false.\";
fi;
fi;
else
if [ -f /etc/pure-ftpd.conf ]
then
if [ `cat /etc/pure-ftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"FortunesFile\"|wc -l` -eq 0 ]
then
echo \"pure-ftpd is running.banner in pure-ftpd.conf is not recommended.FTP check result:false.\";
else
if [ -s \"`cat /etc/pure-ftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"FortunesFile\"|awk '{print \$2}'`\" ];
then
echo \"pure-ftpd is running.Banner in pure-ftpd.conf is recommended.FTP check result:true.\";
else
echo \"pure-ftpd is running.Banner in pure-ftpd.conf is not recommended.FTP check result:false.\";
fi;
fi
fi;
fi;
if [ -f /etc/ftpaccess ];
then
if [ `cat /etc/ftpaccess|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"^[[:space:]]*banner\"|wc -l` -eq 0 ]
then
echo \"wu-ftpd is running.banner in wu-ftpd.conf is not recommended.FTP check result:false.\";
else
if [ -s \"`cat /etc/ftpaccess|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"^[[:space:]]*banner\"|awk '{print \$2}'`\" ];
then
echo \"wu-ftpd is running.Banner in wu-ftpd.conf is recommended.FTP check result:true.\";
else
echo \"wu-ftpd is running.Banner in wu-ftpd.conf is not recommended.FTP check result:false.\";
fi;
fi;
else
if [ -f /etc/ftpd/ftpaccess ]
then
if [ `cat /etc/ftpd/ftpaccess|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"^[[:space:]]*banner\"|wc -l` -eq 0 ]
then
echo \"wu-ftpd is running.banner in wu-ftpd.conf is not recommended.FTP check result:false.\";
else
if [ -s \"`cat /etc/ftpd/ftpaccess|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"^[[:space:]]*banner\"|awk '{print \$2}'`\" ];
then
echo \"wu-ftpd is running.Banner in wu-ftpd.conf is recommended.FTP check result:true.\";
else
echo \"wu-ftpd is running.Banner in wu-ftpd.conf is not recommended.FTP check result:false.\";
fi;
fi;
fi;
fi;
unset FTPCONF;
}
if [ \$FTPSTATUS -eq 0 ];
then
echo \"FTP is not running.FTP check result:true\"
else
Check_ftp;
fi;
unset FTPSTATUS;
";
push(@array_pre_flag, 32);$pre_cmd{33} = "SNMPD_STATUS=`ps -ef|grep snmpd|egrep -v \"grep\"|wc -l`;
Check_SNMPD ()
{
if [ -f /etc/snmp/snmpd.conf ];
then SNMPD_CONF=/etc/snmp/snmpd.conf;
else SNMPD_CONF=/etc/snmpd.conf;
fi;
grep -v \"^#\" \$SNMPD_CONF|egrep \"community\";
if [ `grep -v \"^#\" \$SNMPD_CONF|egrep \"rocommunity|rwcommunity\"|egrep \"public|private\"|wc -l` -eq 0 ];
then echo \"SNMPD is running.SNMP check result:true\";
else echo \"SNMPD is running.SNMP check result:false\";
fi;
}
if [ \"\$SNMPD_STATUS\" -ge  1 ];
then Check_SNMPD;
else echo \"SNMPD is not running.SNMP check result:true\";
fi
unset SNMPD_STATUS SNMPD_CONF;
";
push(@array_pre_flag, 33);$pre_cmd{34} = "up_uidmin=`(grep -v ^# /etc/login.defs |grep \"^UID_MIN\"|awk '(\$1=\"UID_MIN\"){print \$2}')`
up_uidmax=`(grep -v ^# /etc/login.defs |grep \"^UID_MAX\"|awk '(\$1=\"UID_MAX\"){print \$2}')`
egrep -v \"oracle|sybase|postgres\" /etc/passwd|awk -F: '(\$3>='\$up_uidmin' && \$3<='\$up_uidmax') {print \$1\":\"\$3}'
echo \"result=\"`egrep -v \"oracle|sybase|postgres\" /etc/passwd|awk -F: '(\$3>='\$up_uidmin' && \$3<='\$up_uidmax') {print \$1\":\"\$3}'|wc -l`
unset up_uidmin up_uidmax
";
push(@array_pre_flag, 34);$pre_cmd{35} = "echo \"idle_activation_enabled=\"`gconftool-2 -g /apps/gnome-screensaver/idle_activation_enabled`
echo \"lock_enabled=\"`gconftool-2 -g /apps/gnome-screensaver/lock_enabled`
echo \"mode=\"`gconftool-2 -g /apps/gnome-screensaver/mode`
echo \"idle_delay=\"`gconftool-2 -g /apps/gnome-screensaver/idle_delay`
";
push(@array_pre_flag, 35);$pre_cmd{36} = "FTPSTATUS=`ps -ef|grep ftpd|grep -v grep|wc -l`;
Check_ftp ()
{
if [ -f /etc/vsftpd.conf ];
then
FTPCONF=\"/etc/vsftpd.conf\";
else
if [ -f /etc/vsftpd/vsftpd.conf ];
then
FTPCONF=\"/etc/vsftpd/vsftpd.conf\";
fi;
fi;
if [ -f \$FTPCONF ]
then
cat \$FTPCONF|grep -v \"^[[:space:]]*#\"|grep \"ls_recurse_enable\";
cat \$FTPCONF|grep -v \"^[[:space:]]*#\"|grep \"local_umask\";
cat \$FTPCONF|grep -v \"^[[:space:]]*#\"|grep \"anon_umask\";
fi;
if [ -f /etc/pure-ftpd/pure-ftpd.conf ];
then
echo \"pureftp_umask=\"`cat /etc/pure-ftpd/pure-ftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"^[[:space:]]*Umask\"`;
else
if [ -f /etc/pure-ftpd.conf ]
then
echo \"pureftp_umask=\"`cat /etc/pure-ftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"^[[:space:]]*Umask\"`;
fi;
fi;
if [ -f /etc/proftpd.conf ];
then
echo \"proftp_umask=\"`cat /etc/proftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"^[[:space:]]*Umask\"`;
else
if [ -f /etc/proftpd/proftpd.conf ];
then
echo \"proftp_umask=\"`cat /etc/proftpd/proftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"^[[:space:]]*Umask\"`;
else
if [ -f /etc/proftpd/etc/proftpd.conf ];
then
echo \"proftp_umask=\"`cat /etc/proftpd/etc/proftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"^[[:space:]]*Umask\"`;
fi;
fi;
fi;
if [ -f /etc/ftpaccess ];
then
cat /etc/ftpaccess|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"^[[:space:]]*upload\";
else
if [ -f /etc/ftpd/ftpaccess ]
then
cat /etc/ftpd/ftpaccess|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"^[[:space:]]*upload\";
fi;
fi;
unset FTPCONF;
}
if [ \$FTPSTATUS -eq 0 ];
then  echo \"FTP is not running.FTP check result:true.\";
else
Check_ftp;
fi
unset FTPSTATUS;
";
push(@array_pre_flag, 36);$pre_cmd{37} = "ls /etc/rc2.d/* /etc/rc3.d/* /etc/rc4.d/* /etc/rc5.d/* 2>/dev/null|egrep \"lp|rpc|snmpdx|keyserv|nscd|Volmgt|uucp|dmi|sendmail|autoinstall\"|grep \"^S\"
echo \"result=\"` ls /etc/rc2.d/* /etc/rc3.d/* /etc/rc4.d/* /etc/rc5.d/* 2>/dev/null|egrep \"lp|rpc|snmpdx|keyserv|nscd|Volmgt|uucp|dmi|sendmail|autoinstall\"|grep \"^S\"|wc -l`
";
push(@array_pre_flag, 37);$pre_cmd{38} = "uname -a
if [ -f /etc/SuSE-release ];
then
cat /etc/SuSE-release;
uname -a;
else
if [ -f /etc/redhat-release ];
then
cat /etc/redhat-release;
uname -a;
fi;
fi;
";
push(@array_pre_flag, 38);$pre_cmd{39} = "unset red_ret suse_ret suse_ret2 suse_ret3
if [ -s /etc/syslog.conf ];
then red_ret=`cat /etc/syslog.conf | grep -v \"^[[:space:]]*#\" | egrep \"auth\\.\\*[[:space:]]*\\/.*|auth\\.info[[:space:]]*\\/.*\"`
fi
if [ -s /etc/rsyslog.conf ];
then red_ret2=`cat /etc/rsyslog.conf | grep -v \"^[[:space:]]*#\" | egrep \"auth\\.\\*[[:space:]]*\\/.*|auth\\.info[[:space:]]*\\/.*\"`
fi
if [ -s /etc/syslog-ng/syslog-ng.conf ];
then
suse_ret=`cat /etc/syslog-ng/syslog-ng.conf | grep -v \"^[[:space:]]*#\" | grep \"facility(auth)\" | grep \"filter\" | awk '{print \\\$2}'`;
if [ -n \"\$suse_ret\" ];
then suse_ret2=`cat /etc/syslog-ng/syslog-ng.conf | grep -v \"^[[:space:]]*#\" | grep \"destination\" | grep \"/var/log/authlog\"`;
if [ -n \"\$suse_ret2\" ];
then suse_ret3=`cat /etc/syslog-ng/syslog-ng.conf | grep -v \"^[[:space:]]*#\" | grep \"log\" | grep \"\$suse_ret\"`;
fi;
fi;
fi
if [ -n \"\$red_ret\" ];
then
echo \"redhat-suse:valid\";
else
if [ -n \"\$red_ret2\" ];
then
echo \"red-hat6:valid\";
else
if [ -n \"\$suse_ret3\" ];
then
echo \"suse:valid\";
else
echo \"ret:no value\";
fi;
fi;
fi;
unset red_ret suse_ret suse_ret2 suse_ret3;
";
push(@array_pre_flag, 39);$pre_cmd{40} = "unset syslogd_status syslogng_status rsyslogd_status LOGDIR;
syslogd_status=`ps -ef |grep ' syslogd '|grep -v \"grep\"|wc -l`;
syslogng_status=`ps -ef |grep \"syslog-ng\"|grep -v \"grep syslog-ng\"|wc -l`;
rsyslogd_status=`ps -ef | grep \"rsyslogd\" | grep -v \"grep\" |wc -l`;
if [ \"\$syslogd_status\" != 0 ];
then
LOGDIR=`if [ -f /etc/syslog.conf ];then cat /etc/syslog.conf| grep -v \"^[[:space:]]*#\"|awk '((\$2!~/@/) && (\$2!~/*/) && (\$2!~/-/)) {print \$2}';fi`;
ls -l \$LOGDIR 2>/dev/null|grep -v \"[r-][w-]-[r-]-----\"|awk '{print \$1\" \"\$7\" \"\$8\" \"\$9}';
else
if [ \"\$rsyslogd_status\" != 0 ];
then
LOGDIR=`cat /etc/rsyslog.conf | grep -v \"^[[:space:]]*#\"|awk '((\$2!~/@/) && (\$2!~/*/) && (\$2!~/-/)) {print \$2}'`;
ls -l \$LOGDIR 2>/dev/null|grep -v \"[r-][w-]-[r-]-----\"|awk '{print \$1\" \"\$7\" \"\$8\" \"\$9}';
else
if [ \"\$syslogng_status\" != 0 ];
then
LOGDIR=`cat /etc/syslog-ng/syslog-ng.conf|grep -v \"^[[:space:]]*#\"|grep \"^destination\"|grep file|cut -d\\\" -f2`;
ls -l \$LOGDIR 2>/dev/null|grep -v \"[r-][w-]-[r-]-----\"|awk '{print \$1\" \"\$7\" \"\$8\" \"\$9}';
else
echo \"syslog is not running\";
fi;
fi;
fi;
unset syslogd_status syslogng_status rsyslogd_status LOGDIR;
";
push(@array_pre_flag, 40);$pre_cmd{41} = "if ([ -f /etc/redhat-release ] && [ -f /etc/pam.d/system-auth ]);
then FILE=/etc/pam.d/system-auth
cat \$FILE |sed '/^#/d'|sed '/^\$/d'|grep password
fi
suse_version=`cat /etc/SuSE-release 2>/dev/null|grep -i \"VERSION\"|awk '{print \$3}'`
if ([ \"x\$suse_version\" = x10 ] || [ \"x\$suse_version\" = x11 ])
then
FILE=/etc/pam.d/common-password
cat \$FILE|grep -v '^#'|grep -v '^\$'|grep password
else
if [ -f /etc/SuSE-release ]
then
FILE=/etc/pam.d/passwd
cat \$FILE|grep -v '^#'|grep -v '^\$'|grep password
fi
fi
unset suse_version FILE;
";
push(@array_pre_flag, 41);$pre_cmd{42} = "FTPSTATUS=`ps -ef|grep ftpd|grep -v \"grep ftpd\"|wc -l`;
Check_ftp2 ()
{
if [ -f /etc/vsftpd.conf ];
then
FTPCONF=\"/etc/vsftpd.conf\";
FTPUSER=`cat \$FTPCONF|grep -v \"^#\"|grep userlist_file|cut -d= -f2`;
Check_vsftpconf;
else
if [ -f /etc/vsftpd/vsftpd.conf ];
then
FTPCONF=\"/etc/vsftpd/vsftpd.conf\";
FTPUSER=`cat \$FTPCONF|grep -v \"^#\"|grep userlist_file|cut -d= -f2`;
Check_vsftpconf;
fi;
fi;
}
Check_vsftpconf ()
{
userlist_enable=`grep -v \"^#\" \$FTPCONF|grep -i \"userlist_enable=YES\"|wc -l`;
userlist_deny=`grep -v \"^#\" \$FTPCONF|grep -i \"userlist_deny=NO\"|wc -l`;
if  [ \$userlist_enable = 1 -a \$userlist_deny = 1 ];
then
if [ -n \"\$FTPUSER\" ]
then
if [ `grep -v \"^#\" \$FTPUSER|egrep \"^root\$\"|wc -l` = 0 ];
then
echo \"FTP is running.FTP user config \$ftpusers_pam is not recommended.FTP user config \"\$FTPUSER\" is recommended.FTP check result:true\";
else
echo \"FTP is running.FTP user config \$ftpusers_pam is not recommended.FTP user config \"\$FTPUSER\" is not recommended.FTP check result:false\";
fi;
else
echo \"FTP is running.FTP user config \$ftpusers_pam is not recommended.FTP user config \"\$FTPUSER\" does not exist.FTP check result:false\";
fi;
else
echo \"FTP is running.FTP user config \$ftpusers_pam is not recommended.userlist_enable and userlist_deny is not recommended.FTP check result:false\";
fi;
}
Check_ftp1 ()
{
if [ -f  /etc/pam.d/vsftpd ];
then
ftpusers_pam=`grep \"file\" /etc/pam.d/vsftpd|egrep -v \"^#\"|sed 's/^.*file=//g'|awk '{print \$1}'`
if [ -n \"\$ftpusers_pam\" ]
then
if [ `grep -v \"^#\" \$ftpusers_pam|egrep \"^root\$\"|wc -l` = 1 ];
then
echo \"FTP is running.FTP user config \$ftpusers_pam is recommended.FTP check result:true\";
else
Check_ftp2;
fi
else
Check_ftp2;
fi
else
echo \"/etc/pam.d/vsftpd is not exist,scripts exit now\";
Check_ftp2;
fi
if [ -f /etc/proftpd.conf ];
then
if [ `cat /etc/proftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|egrep -i \"RootLogin[[:space:]]*on|wc -l` -eq 0 ]
then
echo \"proftpd is running.FTP check result:true\";
else
echo \"proftpd is running.FTP check result:false\";
fi;
else
if [ -f /etc/proftpd/proftpd.conf ];
then
if [ `cat /etc/proftpd/proftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|egrep -i \"RootLogin[[:space:]]*on|wc -l` -eq 0 ]
then
echo \"proftpd is running.FTP check result:true\";
else
echo \"proftpd is running.FTP check result:false\";
fi;
else
if [ -f /etc/proftpd/etc/proftpd.conf ];
then
if [ `cat /etc/proftpd/etc/proftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|egrep -i \"RootLogin[[:space:]]*on|wc -l` -eq 0 ]
then
echo \"proftpd is running.FTP check result:true\";
else
echo \"proftpd is running.FTP check result:false\";
fi;
fi;
fi;
fi;
if [ -f /etc/ftpusers ];
then
echo \"wu-ftp_users=\"`cat /etc/ftpusers|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep \"^root\"`;
else
if [ -f /etc/ftpd/ftpusers ];
then
echo \"wu-ftp_users=\"`cat /etc/ftpd/ftpusers|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep \"^root\"`;
fi;
fi;
if [ -f /etc/pure-ftpd/pure-ftpd.conf ];
then
cat /etc/pure-ftpd/pure-ftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"MinUID\";
else
if [ -f /etc/pure-ftpd.conf ];
then
cat /etc/pure-ftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"MinUID\";
fi;
fi;
}
if [ \$FTPSTATUS -eq 0 ];
then  echo \"FTP is not running.FTP check result:true\";
else  Check_ftp1;
fi
unset FTPSTATUS FTPCONF FTPUSER ftpusers_pam
";
push(@array_pre_flag, 42);$pre_cmd{43} = "unset red_ret suse_ret suse_ret2 suse_ret3
if [ -s /etc/syslog.conf ];
then red_ret=`cat /etc/syslog.conf | grep -v \"^[[:space:]]*#\" | grep \"authpriv\\.\\*[[:space:]]\\/*\"`;
fi
if [ -s /etc/rsyslog.conf ];
then red_ret2=`cat /etc/rsyslog.conf | grep -v \"^[[:space:]]*#\" | grep \"authpriv\\.\\*[[:space:]]\\/*\"`;
fi
if [ -s /etc/syslog-ng/syslog-ng.conf ];
then
suse_ret=`cat /etc/syslog-ng/syslog-ng.conf | grep -v \"^[[:space:]]*#\" | grep \"facility(authpriv)\" | grep \"filter\" | awk '{print \\\$2}'`;
if [ -n \"\$suse_ret\" ];
then suse_ret2=`cat /etc/syslog-ng/syslog-ng.conf | grep -v \"^[[:space:]]*#\" | grep \"destination\" | grep \"/var/log/secure\"`;
if [ -n \"\$suse_ret2\" ];
then suse_ret3=`cat /etc/syslog-ng/syslog-ng.conf | grep -v \"^[[:space:]]*#\" | grep \"log\" | grep \"\$suse_ret\"`;
fi;
fi;
fi
if [ -n \"\$red_ret\" ];
then
echo \"redhat-suse:valid\";
else
if [ -n \"\$red_ret2\" ];
then
echo \"red-hat6:valid\";
else
if [ -n \"\$suse_ret3\" ];
then
echo \"suse:valid\";
else
echo \"ret:no value\";
fi
fi;
fi;
unset red_ret suse_ret suse_ret2 suse_ret3;
";
push(@array_pre_flag, 43);$pre_cmd{44} = "FTPSTATUS=`ps -ef|grep -v grep|grep -i ftpd|wc -l`
Check_ftp ()
{
if [ -f /etc/vsftpd.conf ];
then
FTPCONF=\"/etc/vsftpd.conf\";
else
if [ -f /etc/vsftpd/vsftpd.conf ];
then
FTPCONF=\"/etc/vsftpd/vsftpd.conf\";
fi;
fi;
if [ -f \"\$FTPCONF\" ];
then
if ([ `grep -v \"^#\" \$FTPCONF|grep -i \"chroot_list_enable=YES\"|wc -l` -eq 1 ] && [ `grep -v \"^#\" /etc/vsftpd/vsftpd.conf|grep -i \"chroot_local_user=YES\"|wc -l` -eq 0 ]);
then
if [ -s \"`grep -v \"^#\" /etc/vsftpd/vsftpd.conf|grep -i \"chroot_list_file\"|cut -d\\= -f2`\" ]
then
echo \"FTP is running.FTP check result:true\"
else
echo \"FTP is running.FTP check result:flase\"
fi
else
echo \"FTP is running.FTP check result:flase\"
fi
fi
if [ -f /etc/pure-ftpd/pure-ftpd.conf ];
then
cat /etc/pure-ftpd/pure-ftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"ChrootEveryone\";
else
if [ -f /etc/pure-ftpd.conf ];
then
cat /etc/pure-ftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"ChrootEveryone\";
fi;
fi;
if [ -f /etc/proftpd.conf ];
then
cat /etc/proftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|egrep -i \"DefaultRoot\";
else
if [ -f /etc/proftpd/proftpd.conf ];
then
cat /etc/proftpd/proftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|egrep -i \"DefaultRoot\";
else
if [ -f /etc/proftpd/etc/proftpd.conf ];
then
cat /etc/proftpd/etc/proftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|egrep -i \"DefaultRoot\";
fi;
fi;
fi;
if [ -f /etc/ftpaccess ];
then
cat /etc/ftpaccess|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"restricted-uid\";
else
if [ -f /etc/ftpd/ftpaccess ];
then
cat /etc/ftpd/ftpaccess|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"restricted-uid\";
fi;
fi;
unset FTPCONF;
}
if [ \$FTPSTATUS -eq 0 ];
then
echo \"FTP is not running.FTP check result:true\";
else
Check_ftp;
fi
unset FTPSTATUS;
";
push(@array_pre_flag, 44);$pre_cmd{45} = "chkconfig --list
netstat -an
";
push(@array_pre_flag, 45);$pre_cmd{46} = "cat /etc/pam.d/su|grep -v \"^[[:space:]]*#\"|grep -v \"^\$\"|grep \"^auth\"
";
push(@array_pre_flag, 46);$pre_cmd{47} = "if [ `ps -ef|grep ftpd|grep -v \"grep\"|wc -l` -ge 1 ];
then
if [ -f /etc/vsftpd.conf ];
then
cat /etc/vsftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"anonymous_enable\";
else
if [ -f /etc/vsftpd/vsftpd.conf ];
then
cat /etc/vsftpd/vsftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"anonymous_enable\";
fi
fi;
if [ -f /etc/ftpaccess ];
then
if ([ `cat /etc/ftpaccess|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep \"^class\\s*[^\\s]\\{1,\\}\\s*.*guest\"|wc -l` -ne 0 ] || [ `cat /etc/ftpaccess|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep \"^class\\s*[^\\s]\\{1,\\}\\s*.*anonymous\"|wc -l` -ne 0 ]);
then
echo \"wu-ftp There are anonymous logins\";
else
echo \"wu-ftp There is no anonymous logins\";
fi;
else
if [ -f /etc/ftpd/ftpaccess ];
then
if ([ `cat /etc/ftpd/ftpaccess|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep \"^class\\s*[^\\s]\\{1,\\}\\s*.*guest\"|wc -l` -ne 0 ] || [ `cat /etc/ftpd/ftpaccess|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep \"^class\\s*[^\\s]\\{1,\\}\\s*.*anonymous\"|wc -l` -ne 0 ]);
then
echo \"wu-ftp There are anonymous logins\";
else
echo \"wu-ftp There is no anonymous logins\";
fi;
fi;
fi;
if [ -f /etc/proftpd.conf ];
then
cat /etc/proftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|egrep -i \"AnonRequirePassword\";
else
if [ -f /etc/proftpd/proftpd.conf ];
then
cat /etc/proftpd/proftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|egrep -i \"AnonRequirePassword\";
else
if [ -f /etc/proftpd/etc/proftpd.conf ];
then
cat /etc/proftpd/etc/proftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|egrep -i \"AnonRequirePassword\";
fi
fi
fi;
if [ -f /etc/pure-ftpd/pure-ftpd.conf ];
then
cat /etc/pure-ftpd/pure-ftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"NoAnonymous\";
else
if [ -f /etc/pure-ftpd.conf ];
then
cat /etc/pure-ftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"NoAnonymous\";
fi;
fi;
else
echo \"ftp is not running,result=true\";
fi;
";
push(@array_pre_flag, 47);$pre_cmd{48} = "redhat_count=0
suse_count=0
result=0
telnet_status=`netstat -an|grep \":23\\>\"|grep -i listen|wc -l`;
if [ -s /etc/issue ]
then cat /etc/issue
redhat_count=`cat /etc/issue | grep -i \"Red Hat\" | wc -l`
suse_count=`cat /etc/issue | grep -i \"suse\" | wc -l`
fi
if ([ \$redhat_count -ge 1 ] || [ \$suse_count -ge 1 ])
then result=1
fi
if [ -s /etc/issue.net ]
then cat /etc/issue.net
redhat_count=`cat /etc/issue.net | grep -i \"Red Hat\" | wc -l`
suse_count=`cat /etc/issue.net | grep -i \"suse\" | wc -l`
fi
if ([ \$redhat_count -ge 1 ] || [ \$suse_count -ge 1 ])
then result=1
fi
if ([ \$result = 1 ] && [ \$telnet_status = 1 ]);
then
echo \"telnet is running.telnet banner is not valid.telnet banner check result:false\";
else
if [ \$result = 1 ];
then
echo \"telnet is not running.telnet banner is not valid.telnet banner check result:true\";
else
if [ \$telnet_status = 1 ];
then
echo \"telnet is running.telnet banner is valid.telnet banner check result:true\";
else
echo \"telnet is not running.telnet banner is valid.telnet banner check result:true\";
fi;
fi;
fi;
unset redhat_count suse_count result
";
push(@array_pre_flag, 48);$pre_cmd{49} = "if [ -f /etc/syslog.conf ]
then
echo \"syslog=\"`cat /etc/syslog.conf | grep -v \"^[[:space:]]*#\" | grep \"cron.\\*\"`
fi
if [ -f /etc/rsyslog.conf ]
then
echo \"rsyslog=\"`cat /etc/rsyslog.conf | grep -v \"^[[:space:]]*#\" | grep \"cron.\\*\"`
fi
if [ -s /etc/syslog-ng/syslog-ng.conf ];
then
cron_1=`cat /etc/syslog-ng/syslog-ng.conf | grep -v \"^[[:space:]]*#\" | grep \"filter[[:space:]]*.*[[:space:]]*{[[:space:]]*facility(cron);[[:space:]]*};\" | wc -l`;
if [ \$cron_1 -ge 1 ];
then
cron_2=`cat /etc/syslog-ng/syslog-ng.conf | grep -v \"^[[:space:]]*#\" | grep \"destination[[:space:]]*.*[[:space:]]*{[[:space:]]*file(\\\"/var/log/cron\\\")[[:space:]]*;[[:space:]]*};\"|awk '{print \$2}'`;
if [ -n \$cron_2 ];
then
cron_3=`cat /etc/syslog-ng/syslog-ng.conf | grep -v \"^[[:space:]]*#\" | grep \"log[[:space:]]*{[[:space:]]*source(src);[[:space:]]*filter(.*);[[:space:]]*destination(\$cron_2);[[:space:]]*};\" | wc -l`;
if [ \$cron_3 -ge 1 ]
then
echo \"Cron log has been configured,check result:true\";
else
echo \"No cron log,check result:false\";
fi;
fi;
fi;
fi;
";
push(@array_pre_flag, 49);$pre_cmd{50} = "lsattr /var/log/messages 2>/dev/null
";
push(@array_pre_flag, 50);$pre_cmd{51} = "cat /proc/sys/net/ipv4/conf/*/accept_source_route
";
push(@array_pre_flag, 51);$pre_cmd{52} = "cat /proc/sys/net/ipv4/tcp_syncookies
";
push(@array_pre_flag, 52);$pre_cmd{53} = "cat /etc/host.conf|grep -v \"^[[:space:]]*#\"|egrep \"order[[:space:]]hosts,bind|multi[[:space:]]on|nospoof[[:space:]]on\"
";
push(@array_pre_flag, 53);$pre_cmd{54} = "cat /etc/profile|grep -v \"^[[:space:]]*#\"|grep \"HISTFILESIZE\"
cat /etc/profile|grep -v \"^[[:space:]]*#\"|grep \"HISTSIZE\"
";
push(@array_pre_flag, 54);$pre_cmd{55} = "if [ `echo \$SHELL|egrep \"bash|sh\"|wc -l` -ge 1 ]
then
cat /root/.bashrc|grep -v \"^[[:space:]]*#\"
else
cat /root/.cshrc|grep -v \"^[[:space:]]*#\"
fi
";
push(@array_pre_flag, 55);$pre_cmd{4596} = "openssl version
";
push(@array_pre_flag, 4596);$pre_cmd{4597} = "env -i  X='() { (a)=>\\' bash -c '/dev/stdout echo vulnerable'  2>/dev/null
";
push(@array_pre_flag, 4597);


sub get_os_info
{
	my %os_info = (
 "initSh"=>"","hostname"=>"","osname"=>"","osversion"=>"");
 $os_info{"initSh"} = `unset LANG`;
	$os_info{"hostname"} = `uname -n`;
	$os_info{"osname"} = `uname -s`;
	$os_info{"osversion"} = `lsb_release -a;cat /etc/issue;cat /etc/redhat-release;uname -a`;
	foreach (%os_info){   chomp;}
	return %os_info;
}

sub add_item
{
	 my ($string, $flag, $value)= @_;
	 $string .= "\t\t".'<script>'."\n";
	 $string .= "\t\t\t<id>$flag</id>\n";
	 $string .= "\t\t\t<value><![CDATA[$value]]></value>\n";
	 $string .= "\t\t</script>\n";
	return $string;
}
sub generate_xml
{
	$ARGC = @ARGV;
	if($ARGC lt 1)
	{
		print qq{usag:uuid.pl IP };
		exit;
	}
	my %os_info = get_os_info();
	my $os_name = $os_info{"osname"};
	my $host_name = $os_info{"hostname"};
	my $os_version = $os_info{"osversion"};
	my $date = ` date "+%Y-%m-%d %H:%M:%S"`;
	chomp $date;
	my $coding = `echo \$LANG`;
	my $coding_value = "UTF-8";
	chomp $coding;
	if($coding =~ "GB")
	{
        $coding_value = "GBK"
    }
	my $ipaddr = $ARGV[0];
	my $xml_string = "";
	
	$xml_string .='<?xml version="1.0" encoding="'.$coding_value.'"?>'."\n";
	$xml_string .='<result>'."\n";
	$xml_string .= '<osName><![CDATA['."$os_name".']]></osName>'."\n";
	$xml_string .= '<version><![CDATA['."$os_version".']]></version>'."\n";
	$xml_string .= '<ip><![CDATA['."$ipaddr".']]></ip>'."\n";
	$xml_string .= '<type><![CDATA[/server/Linux]]></type>'."\n";
	$xml_string .= '<startTime><![CDATA['."$date".']]></startTime>'."\n";
	$xml_string .= '<pId><![CDATA[3]]></pId>'."\n";

	$xml_string .=	"\t".'<scripts>'."\n";
	
	foreach $key (@array_pre_flag)
	{
		$value = $pre_cmd{$key};
		my $tmp_result = `$value`;
		chomp $tmp_result;
		$tmp_result =~ s/>/&gt;/g;
		$tmp_result =~ s/[\x00-\x08\x0b-\x0c\x0e-\x1f]//g;
		$xml_string = &add_item( $xml_string, $key, $tmp_result );
	}
	$xml_string .= "\t</scripts>\n";
	
	my $enddate = ` date "+%Y-%m-%d %H:%M:%S"`;
	$xml_string .= '<endTime><![CDATA['."$enddate".']]></endTime>'."\n";
	
	$xml_string .= "</result>"."\n";
	$xmlfile = $ipaddr."_"."linux"."_chk.xml";
	print $xmlfile."\n";
	open XML,">/tmp/".$xmlfile or die "Cannot create ip.xml:$!";
	print XML $xml_string;
	print "end write xml\n";
	print "DONE ALL\n";
 }
 generate_xml();
