#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter_ipv4.h>
#include <linux/proc_fs.h>
#include <linux/timer.h>
#include <net/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

/* Version Info */
#define VERSION		"1.03"
#define VERSIONINFO	"CIF v" VERSION " Build " __TIME__ " " __DATE__

/* Time update frequency, doh */
#define TIMEUPDATEFREQ	10

/* Time to determine current HZ value */
#define HZCHECKSECS	10

/* Various strings */
#define MSGHEADER		"cif - "
#define PROCFILENAME	"aibgrebulon"

/* Table Header (hmm?) */
#define TABLEHEADER		" _#_   ___Source IP___   SPort   ____Dest IP____   DPort   ____ID____   Prt   Last Seen_\n ---------------------------------------------------------------------------------------\n"

/* Macros */
#define CURPORT			(portrules[i])
#define CURRULE			(iprules[i])

/* Command line limits */
#define TIMEOUT_MIN		10
#define TIMEOUT_DEFAULT	30
#define TIMEOUT_MAX		600

#define RULES_MIN		10
#define RULES_DEFAULT	50
#define RULES_MAX		200

#define PORTS_MIN		1
#define PORTS_DEFAULT	20
#define PORTS_MAX		32

#define MAXPARAMS		7
#define MAXPARAMSIZE	20

/* IPRule flags */
#define IRF_ENABLED		0x01
#define IRF_PERMANENT	0x02
#define IRF_SPORTFIRST	0x04
#define IRF_SPORTANY	0x08
#define IRF_REPORT		0x80

/* PortRule flags */
#define PRF_ENABLED		0x01

/* Protocols */
#define KPROTOCOL_TCP	1
#define KPROTOCOL_UDP	2

/* ctlRule options */
//#define CTL_ENABLE		1
#define CTL_DISABLE		2
#define CTL_TIMEDOUT	3

/* Prototypes */
static unsigned int moduleHook(unsigned int hooknum, struct sk_buff **skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *));
static void timerCheckHz(unsigned long unused);
static void timerCheck(unsigned long unused);
static void ctlRule(int ruleNum, int whattodo);
static int module_proc_read(char *page, char **start, off_t off, int count, int *eof, void *data);
static int module_proc_write(struct file *file, const char *buffer, unsigned long count, void *data);
static int match_port_rule(__u16 port, __u32 ip);
static int add_port_rule(__u16 port, __u32 ip);
static int remove_port_rule(__u16 port, __u32 ip);
static int add_ip_rule(__u32 src_ip, __u32 dst_ip, __u16 src_port, __u16 dst_port, __u8 flags, __u16 rule_id, __u8 protocol);
//static int remove_ip_rule(__u32 src_ip, __u32 dst_ip, __u16 src_port, __u16 dst_port, __u8 protocol);
static int remove_ip_rule_by_id(__u16 rule_id);
static int kstrimatch(char *x, char *y);
static int moduleInit(void) __init;
static void moduleExit(void) __exit;

/* Define entry/exit points */
module_init(moduleInit);
module_exit(moduleExit);

/* IP Rule Format */
typedef struct {
	__u8	flags;

	__u32	src_ip;
	__u32	dst_ip;
	__u16	src_port;
	__u16	dst_port;
	
	time_t	firstseen;
	time_t	lastseen;

	__u8	protocol;	
	__u16	rule_id;
} IPRule;

/* Port Rule Format */
typedef struct {
	__u8	flags;
	
	__u16	port;
	__u32	ip;
} PortRule;

/* Firewall rules */
static short maxrules = RULES_DEFAULT;
static short maxports = PORTS_DEFAULT;
static short ruletimeout = TIMEOUT_DEFAULT;

MODULE_PARM(maxrules, "h");
MODULE_PARM(maxports, "h");
MODULE_PARM(ruletimeout, "h");

/* Global variables */
static IPRule	*iprules;
static PortRule	*portrules;

static struct timer_list timerEntry;

static time_t ourCurrentTime;

static struct timer_list timerHz; /* HZCHECK */
static time_t hz_currentTime = 0; /* HZCHECK */
static unsigned long currentHz = HZ; /* HZCHECK */

static struct proc_dir_entry *procfile;

static struct nf_hook_ops hookops = {
	{ NULL, NULL },
	moduleHook,
	PF_INET,
	NF_IP_LOCAL_IN,
	NF_IP_PRI_CONNTRACK
};

static unsigned int moduleHook(unsigned int hooknum,
						struct sk_buff **skb,
						const struct net_device *in,
						const struct net_device *out,
						int (*okfn)(struct sk_buff *))
{
#define SKB		(*skb)
#define IPH		(SKB->nh.iph)
#define TCPH	((struct tcphdr *) (SKB->data + (IPH->ihl << 2)))
#define UDPH	((struct udphdr *) (SKB->data + (IPH->ihl << 2)))
#define ITON(x)	(((x & 0xFF00) >> 8) | ((x & 0x00FF) << 8))

#define tsport	ITON(TCPH->source)
#define tdport	ITON(TCPH->dest)
#define usport	ITON(UDPH->source)
#define udport	ITON(UDPH->dest)
	int istcp;

	if (SKB == NULL) return NF_ACCEPT;	/* packet info is NULL */
	if (IPH == NULL) return NF_ACCEPT;	/* IP header is NULL */
	
	if (IPH->protocol == IPPROTO_TCP) istcp = 1;		/* this is TCP */
	else if (IPH->protocol == IPPROTO_UDP) istcp = 0;	/* this is UDP */
	else return NF_ACCEPT;								/* this is none of our business */
	
	/* since SKB->h is a union, checking for either one of TCPH/UPDH for NULLness is OK. */
	if (TCPH == NULL) return NF_ACCEPT;

	if (istcp) { /* TCP */
		if (!match_port_rule(tdport, IPH->daddr)) return NF_ACCEPT; /* I am not watching the port */
		
		register int i;
	
		for(i=0; i<maxrules; ++i) {
			if ((CURRULE.flags & IRF_ENABLED) && (CURRULE.protocol == KPROTOCOL_TCP)) {
				if ((CURRULE.flags & IRF_SPORTFIRST) && !CURRULE.src_port) {
					if ((CURRULE.src_ip == IPH->saddr) && (CURRULE.dst_ip == IPH->daddr) && (CURRULE.dst_port == tdport)) {
//						CURRULE.flags &= ~IRF_SPORTFIRST;
						CURRULE.src_port = tsport;
						CURRULE.lastseen = ourCurrentTime;
						return NF_ACCEPT;
					}
				} else if (CURRULE.flags & IRF_SPORTANY) {
					if ((CURRULE.src_ip == IPH->saddr) && (CURRULE.dst_ip == IPH->daddr) && (CURRULE.dst_port == tdport)) {
						CURRULE.lastseen = ourCurrentTime;
						return NF_ACCEPT;
					}
				} else {
					if ((CURRULE.src_ip == IPH->saddr) && (CURRULE.src_port == tsport) && (CURRULE.dst_ip == IPH->daddr) && (CURRULE.dst_port == tdport)) {
						return NF_ACCEPT;
						CURRULE.lastseen = ourCurrentTime;
					}
				}
			}
		}
		
		return NF_DROP;
	} else { /* UDP */
		if (!match_port_rule(udport, IPH->daddr)) return NF_ACCEPT; /* I am not watching the port */

		register int i;
	
		for(i=0; i<maxrules; ++i) {
			if ((CURRULE.flags & IRF_ENABLED) && (CURRULE.protocol == KPROTOCOL_UDP)) {
				if ((CURRULE.flags & IRF_SPORTFIRST) && !CURRULE.src_port) {
					if ((CURRULE.src_ip == IPH->saddr) && (CURRULE.dst_ip == IPH->daddr) && (CURRULE.dst_port == udport)) {
//						CURRULE.flags &= ~IRF_SPORTFIRST;
						CURRULE.src_port = usport;
						CURRULE.lastseen = ourCurrentTime;
						return NF_ACCEPT;
					}
				} else if (CURRULE.flags & IRF_SPORTANY) {
					if ((CURRULE.src_ip == IPH->saddr) && (CURRULE.dst_ip == IPH->daddr) && (CURRULE.dst_port == udport)) {
						CURRULE.lastseen = ourCurrentTime;
						return NF_ACCEPT;
					}
				} else {
					if ((CURRULE.src_ip == IPH->saddr) && (CURRULE.src_port == usport) && (CURRULE.dst_ip == IPH->daddr) && (CURRULE.dst_port == udport)) {
						CURRULE.lastseen = ourCurrentTime;
						return NF_ACCEPT;
					}
				}
			}
		}
		
		return NF_DROP;
	}
}

/* HZCHECK */
static void timerCheckHz(unsigned long u)
{
	time_t timeDiff;
	 
	if ((timeDiff = CURRENT_TIME - hz_currentTime) < 1) {
    	printk(KERN_WARNING MSGHEADER "Unable to determine kernel HZ. Falling back to %u.\n", (unsigned int) currentHz);
    } else {
	    unsigned long chz;
		// HZCHECKSECS / timeDiff = compiledhz * currenthz
		// 10 / 1 = HZ*10
	    chz = HZCHECKSECS / timeDiff * HZ;
    	printk(KERN_INFO MSGHEADER "We are running at %u HZ.\n", (unsigned int) chz);
	    currentHz = chz;
    }
}
/* HZCHECK */

static void timerCheck(unsigned long unused)
{
	register int i;
	
	ourCurrentTime = CURRENT_TIME;
	
	for(i=0; i<maxrules; ++i)
		if ((CURRULE.flags & IRF_ENABLED) && !(CURRULE.flags & IRF_PERMANENT))
			if ((CURRENT_TIME - ruletimeout) > CURRULE.lastseen)
				ctlRule(i, CTL_TIMEDOUT);
//				CURRULE.flags &= ~IRF_ENABLED;
	
	/* Re-initialize timer */	
	init_timer(&timerEntry);
	timerEntry.expires = jiffies+(TIMEUPDATEFREQ*currentHz);
 	timerEntry.function = timerCheck;
 	add_timer(&timerEntry);
}

static void ctlRule(int ruleNum, int whattodo)
{
	if ((whattodo == CTL_DISABLE) || (whattodo == CTL_TIMEDOUT)) {
		int timediff = 0;
	
		if (iprules[ruleNum].flags & IRF_ENABLED) {
			if (whattodo == CTL_TIMEDOUT)
				timediff = -ruletimeout;
				
			/* rule id - conn. time - dest ip:dest port - protocol */
			printk(KERN_NOTICE "cifiplog - %u %u %u.%u.%u.%u:%u %s now=%u\n", iprules[ruleNum].rule_id, (CURRENT_TIME - iprules[ruleNum].firstseen)+timediff, NIPQUAD(iprules[ruleNum].dst_ip), iprules[ruleNum].dst_port, ((iprules[ruleNum].protocol == KPROTOCOL_TCP)?"TCP":((iprules[ruleNum].protocol == KPROTOCOL_UDP)?"UDP":"N/A")), CURRENT_TIME);
			iprules[ruleNum].flags &= ~IRF_ENABLED;
		}
	}
}


static int module_proc_read(char *page, char **start, off_t off, int count, int *eof, void *data)
{
	register int i;
	char ips[16], ipd[16];
	int len = 0;
	off_t begin = 0;
	char protoname[4];

	len = sprintf(page, "Ports on watch: ");
	
	for(i=0; i<maxports; ++i)
		if (CURPORT.flags & PRF_ENABLED)
			len += sprintf(page+len, "%u.%u.%u.%u:%u, ", NIPQUAD(CURPORT.ip), CURPORT.port);
		
	len += sprintf(page+len, "\n%s", TABLEHEADER);

	for(i=0; i<maxrules; ++i) {
		if (CURRULE.flags & IRF_ENABLED) {
			sprintf(ips, "%u.%u.%u.%u", NIPQUAD(CURRULE.src_ip));
			sprintf(ipd, "%u.%u.%u.%u", NIPQUAD(CURRULE.dst_ip));
			if (CURRULE.protocol == KPROTOCOL_TCP) {
				sprintf(protoname, "TCP");
			} else if (CURRULE.protocol == KPROTOCOL_UDP) {
				sprintf(protoname, "UDP");
			} else {
				sprintf(protoname, "N/A");
			}

			if (CURRULE.flags & IRF_PERMANENT)
				len += sprintf(page+len, "\033[1;37m");
						
			if ((CURRULE.flags & IRF_SPORTFIRST) && !CURRULE.src_port) {
				len += sprintf(page+len, " %3u   %15s       *   %15s   %5u   %10u   %s   %10u\n", i, ips, ipd, CURRULE.dst_port, CURRULE.rule_id, protoname, CURRENT_TIME - CURRULE.lastseen);
			} else if (CURRULE.flags & IRF_SPORTANY) {
				len += sprintf(page+len, " %3u   %15s   -ANY-   %15s   %5u   %10u   %s   %10u\n", i, ips, ipd, CURRULE.dst_port, CURRULE.rule_id, protoname, CURRENT_TIME - CURRULE.lastseen);
			} else {
				len += sprintf(page+len, " %3u   %15s   %5u   %15s   %5u   %10u   %s   %10u\n", i, ips, CURRULE.src_port, ipd, CURRULE.dst_port, CURRULE.rule_id, protoname, CURRENT_TIME - CURRULE.lastseen);
			}
		
			if (CURRULE.flags & IRF_PERMANENT)
				len += sprintf(page+len, "\033[0;37m");
		}
		
		if (len+begin > off+count)
			break;

		if (len+begin < off) {
			begin += len;
			len = 0;
		}
	}
	
	if (i == maxrules)
		*eof = 1;
		
	if (off >= len+begin)
		return 0;
		
	*start = page + (off-begin);
	
	return ((count < begin+len-off) ? count : begin+len-off);
}

static int module_proc_write(struct file *file, const char *buffer, unsigned long count, void *data)
{
	char param[MAXPARAMS][MAXPARAMSIZE];
	int p, c, b;
	int opt_add, opt_remove;
	
	b = 0;
	for(p=0; p<MAXPARAMS; ++p) {
		for(c=0; c<MAXPARAMSIZE; ++c) {
			if ((param[p][c] = buffer[b++]) == ' ') { /* end of parameter */
				param[p][c] = '\0';
				break;
			}
			
			if (b == count) { /* clean up and exit */
				param[p][c++] = '\0';
				++p;
				goto done;
			}
		}
	}
	done:

	if ((p == 7) && ((opt_add = kstrimatch(param[0], "addip")))) {
		unsigned int a1,a2,a3,a4;
		__u32 sip, dip;
		__u16 sport, dport, rule_id;
		__u8 flags = 0x00; /* adettendir */
		__u8 protocol;
		
		if ((sscanf(param[1], "%u.%u.%u.%u", &a1, &a2, &a3, &a4) != 4) || ((a1 | a2 | a3 | a4) > 255)) {
			printk(KERN_WARNING MSGHEADER "Invalid source IP for IP rule.\n");
			goto notdone;
		} else {
			sip = ((a4<<24) | (a3<<16) | (a2<<8) | (a1));
		}
		
		sport = 0;
		if (kstrimatch(param[2], "*")) {
			flags |= IRF_SPORTFIRST;
		} else if (kstrimatch(param[2], "!")) {
			flags |= (IRF_PERMANENT | IRF_SPORTANY);
		} else if (kstrimatch(param[2], "?")) {
			flags |= IRF_SPORTANY;
		} else {
			if ((sscanf(param[2], "%u", &a1) != 1) || (a1 > 65535)) {
				printk(KERN_WARNING MSGHEADER "Invalid source port for IP rule.\n");
				goto notdone;
			} else {
				sport = a1;
			}
		}
		
		if ((sscanf(param[3], "%u.%u.%u.%u", &a1, &a2, &a3, &a4) != 4) || ((a1 | a2 | a3 | a4) > 255)) {
			printk(KERN_WARNING MSGHEADER "Invalid destination IP for IP rule.\n");
			goto notdone;
		} else {
			dip = ((a4<<24) | (a3<<16) | (a2<<8) | (a1));
		}
		
		if ((sscanf(param[4], "%u", &a1) != 1) || (a1 > 65535)) {
			printk(KERN_WARNING MSGHEADER "Invalid source port for IP rule.\n");
			goto notdone;
		} else {
			dport = a1;
		}
		
		if (kstrimatch(param[5], "TCP")) {
			protocol = KPROTOCOL_TCP;
		} else if (kstrimatch(param[5], "UDP")) {
			protocol = KPROTOCOL_UDP;
		} else {
			printk(KERN_WARNING MSGHEADER "Invalid protocol for IP rule.\n");
			goto notdone;
		}
 
		if (sscanf(param[6], "%u", &a1) != 1) {
			printk(KERN_WARNING MSGHEADER "Invalid rule id for IP rule.\n");
			goto notdone;
		} else {
			rule_id = a1;
		}
					
		add_ip_rule(sip, dip, sport, dport, flags, rule_id, protocol);
		
	/* END OF 'addip' */
	
	} else if ((p == 3) && ((opt_add = kstrimatch(param[0], "addport")) || (opt_remove = kstrimatch(param[0], "removeport")))) {
		unsigned int b1,b2,b3,b4;
		unsigned int b;
		
		__u16 port;
		__u32 ip;

		if ((sscanf(param[1], "%u", &b) != 1) || (b > 65535)) {
			printk(KERN_WARNING MSGHEADER "Invalid port for port rule.\n");
			goto notdone;
		} else {
			port = b;
		}
		
		if ((sscanf(param[2], "%u.%u.%u.%u", &b1, &b2, &b3, &b4) != 4) || ((b1 | b2 | b3 | b4) > 255)) {
			printk(KERN_WARNING MSGHEADER "Invalid IP for port rule.\n");
			goto notdone;
		} else {
			ip = ((b4<<24) | (b3<<16) | (b2<<8) | (b1));
		}
	
		if (opt_add) {
			add_port_rule(port, ip);
		} else if (opt_remove) {
			remove_port_rule(port, ip);
		}
	
	/* END OF 'addport' or 'removeport' */
	
	} else if ((p == 2) && (kstrimatch(param[0], "delip"))) {
		unsigned int c;
		
		if ((sscanf(param[1], "%u", &c) != 1) || (c >= maxrules) || (!(iprules[c].flags & IRF_ENABLED))) {
			printk(KERN_WARNING MSGHEADER "Invalid ip rule # to delete.\n");
			goto notdone;
		} else {
			ctlRule(c, CTL_DISABLE);
//			iprules[c].flags &= ~IRF_ENABLED;
		}
	
	/* END OF 'delip' */
	
	} else if ((p == 2) && (kstrimatch(param[0], "removeid"))) {
		unsigned int c;
		
		if (sscanf(param[1], "%u", &c) != 1) {
			printk(KERN_WARNING MSGHEADER "Invalid ip ruleid to remove.\n");
			goto notdone;
		} else {
		    if (remove_ip_rule_by_id(c)!=1) {
			printk(KERN_WARNING MSGHEADER "removeid failed.\n");			
			}
		}
	
	/* END OF 'removeid' */
	
	} else if ((p == 1) && (kstrimatch(param[0], "renewsourceports"))) {
		register int i;
	
		printk(KERN_INFO "renewing source ports.\n");
		
		for(i=0; i<maxrules; ++i)
			if ((CURRULE.flags & IRF_ENABLED) && (CURRULE.flags & IRF_SPORTFIRST))
				CURRULE.src_port = 0;
	
	/* END OF 'renewsourceports' */
	
	}
		
	notdone:
	
	return count;
}

static int match_port_rule(__u16 port, __u32 ip)
{
	register int i;
	
	for(i=0; i<maxports; ++i) {
		if (CURPORT.flags & PRF_ENABLED)
			if ((CURPORT.port == port) && (CURPORT.ip == ip))
				return 1;
	}
	
	return 0;
}

static int add_port_rule(__u16 port, __u32 ip)
{
	register int i;

	if (match_port_rule(port, ip)) return -1;
		
	for(i=0; i<maxports; ++i) {
		if (!(CURPORT.flags & PRF_ENABLED)) {
			CURPORT.port = port;
			CURPORT.ip = ip;
			CURPORT.flags = PRF_ENABLED;
			return i;
		}
	}
	
	return -1;
}

static int remove_port_rule(__u16 port, __u32 ip)
{
	register int i;
	
	for(i=0; i<maxports; ++i) {
		if (CURPORT.flags & PRF_ENABLED)
			if ((CURPORT.port == port) && (CURPORT.ip == ip)) {
				CURPORT.flags &= ~PRF_ENABLED;
				return 1;
			}
	}

	return 0;
}

static int add_ip_rule(__u32 src_ip, __u32 dst_ip, __u16 src_port, __u16 dst_port, __u8 flags, __u16 rule_id, __u8 protocol)
{
	register int i;
	
	for(i=0; i<maxrules; ++i)
		if (CURRULE.flags & IRF_ENABLED)
			if (
				(CURRULE.src_ip == src_ip) &&
				(CURRULE.dst_ip == dst_ip) &&
				(CURRULE.protocol == protocol) &&
				(((CURRULE.flags & IRF_SPORTANY) && (flags & IRF_SPORTANY)) || !((flags & IRF_SPORTFIRST) || ((flags & IRF_SPORTANY) || (CURRULE.src_port != src_port)))) &&
//				(((CURRULE.flags ^ flags) & (IRF_SPORTFIRST | IRF_SPORTANY)) ? 0 : ((CURRULE.flags & (IRF_SPORTFIRST | IRF_SPORTANY)) ? 1 : (CURRULE.src_port == src_port))) &&
				(CURRULE.dst_port == dst_port)
			   )
				return -1;
			
	for(i=0; i<maxrules; ++i)
		if (!(CURRULE.flags & IRF_ENABLED)) {
			CURRULE.src_ip = src_ip;
			CURRULE.dst_ip = dst_ip;
			CURRULE.src_port = src_port;
			CURRULE.dst_port = dst_port;
			CURRULE.rule_id = rule_id;
			CURRULE.firstseen = CURRULE.lastseen = CURRENT_TIME;
			CURRULE.protocol = protocol;
			CURRULE.flags = IRF_ENABLED | flags;
			return i;
		}

	return -1;
}

/*
static int remove_ip_rule(__u32 src_ip, __u32 dst_ip, __u16 src_port, __u16 dst_port, __u8 protocol)
{
	register int i;
	
	for(i=0; i<maxrules; ++i)
		if (CURRULE.flags & IRF_ENABLED)
			if ((CURRULE.src_ip == src_ip) && (CURRULE.src_port == src_port) && (CURRULE.dst_ip == dst_ip) && (CURRULE.dst_port == dst_port) && (CURRULE.protocol == protocol)) {
				CURRULE.flags &= ~IRF_ENABLED;
				return 1;
			}

	return 0;
}
*/

static int remove_ip_rule_by_id(__u16 rule_id)
{
	register int i;
	
	for(i=0; i<maxrules; ++i)
		if (CURRULE.flags & IRF_ENABLED)
			if (CURRULE.rule_id == rule_id)
				ctlRule(i, CTL_DISABLE);
//				CURRULE.flags &= ~IRF_ENABLED;

	return 0;
}

static int kstrimatch(char *x, char *y)
{
	register int c;
	
	do {
		c = ((*x | 32) == (*y | 32));
	} while (*x++ && *y++ && c);
	
	return c;
}

static int __init moduleInit(void)
{
	printk(KERN_NOTICE MSGHEADER "called.\n");

	/* Parameter checking */
	if ((maxports < PORTS_MIN) || (maxports > PORTS_MAX)) {
		printk(KERN_ERR MSGHEADER "Invalid number of maximum watch ports 'maxports=%u'!\n", maxports);
		return -2;
	}
	if ((maxrules < RULES_MIN) || (maxrules > RULES_MAX)) {
		printk(KERN_ERR MSGHEADER "Invalid number of maximum rules 'maxrules=%u'!\n", maxrules);
		return -3;
	}
	
	/* Memory allocation */
	if ((portrules = kmalloc(sizeof(PortRule) * maxports, GFP_KERNEL)) == NULL) {
		printk(KERN_ERR MSGHEADER "Unable to allocate memory for %u ports!\n", maxports);
		return -129;
	}
	if ((iprules = kmalloc(sizeof(IPRule) * maxrules, GFP_KERNEL)) == NULL) {
		printk(KERN_ERR MSGHEADER "Unable to allocate memory for %u rules!\n", maxrules);
		return -130;
	}

	/* Clean rule tables */
	register int i;
	for(i=0; i<maxports; ++i)
		portrules[i].flags &= ~PRF_ENABLED;
	for(i=0; i<maxrules; ++i)
		iprules[i].flags &= ~IRF_ENABLED;
	
	/* Create /proc file for communications */
	if ((procfile = create_proc_entry(PROCFILENAME, S_IFREG | S_IRUSR | S_IWUSR, &proc_root)) == NULL) {
		printk(KERN_ERR MSGHEADER "Unable to create communications file.\n");
		return -6;
	}

	/* Modify /proc file */
	procfile->size = 666; /* Please kill me prior to changing this */
	procfile->read_proc = module_proc_read;
	procfile->write_proc = module_proc_write;		

	/* Initialize the timer to determine HZ - HZCHECK */
	init_timer(&timerHz);
	timerHz.expires = jiffies+(HZCHECKSECS*HZ);
 	timerHz.function = timerCheckHz;
	hz_currentTime = CURRENT_TIME;
 	add_timer(&timerHz);

	ourCurrentTime = CURRENT_TIME;
	
	/* Initialize timer */
	init_timer(&timerEntry);
	timerEntry.expires = jiffies+(TIMEUPDATEFREQ*HZ);
 	timerEntry.function = timerCheck;
 	add_timer(&timerEntry);
	
	/* Netfilter hooking */
	if (nf_register_hook(&hookops)) {
		printk(KERN_ERR MSGHEADER "Unable to hook IP input!\n");
		return -1;
	} else {
		printk(KERN_INFO MSGHEADER "Hooked IP input with %u ports, %u rules and with %u seconds of timeout.\n", maxports, maxrules, ruletimeout);
	}

	printk(KERN_NOTICE MSGHEADER VERSIONINFO " running.\n");

	return 0;
}

static void __exit moduleExit(void)
{
	printk(KERN_NOTICE MSGHEADER "exiting.\n");
	
	del_timer_sync(&timerHz); /* HZCHECK */
	del_timer_sync(&timerEntry);
	nf_unregister_hook(&hookops);
	remove_proc_entry(PROCFILENAME, &proc_root);
	
	/* Kill all rules and update connection times */
	register int i;
	for(i=0; i<maxrules; ++i)
		ctlRule(i, CTL_DISABLE);

	/* Free tables */
	kfree(iprules);
	kfree(portrules);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("aib");
