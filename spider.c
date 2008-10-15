#define _LARGEFILE_SOURCE 1
#define _LARGEFILE64_SOURCE 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <libgen.h>
#include <pwd.h>
#include <syslog.h>
#include <time.h>
#include <ctype.h>
#include <signal.h>

#include <sys/time.h>
#include <utime.h>

#include <errno.h>
#include <math.h>

// simple regex matching for path skips
#include <regex.h>
//
// generic encryption functions.  we'll Blowfish our log files
#include <openssl/evp.h>
#include <openssl/md5.h>

// autotools config file for portability
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

// archive handlers
#ifdef HAVE_LIBZ
#include <zlib.h>
#endif /* HAVE_LIBZ */

#ifdef HAVE_LIBBZ2
#include <bzlib.h>
#endif /* HAVE_LIBBZ2 */

#ifdef HAVE_LIBZZIP
#include <zzip/zzip.h>
#endif /* HAVE_LIBZZIP */

// XML parser
#include <expat.h>

// our config file; we'll internalize this when we go under Glade
#include "spider_config.h"

#define BUF_SIZE	65535
#define MATCH_WIDTH	128

#ifdef HAVE_LIBMAGIC
#include <magic.h>
int magic_flags = MAGIC_NONE;
magic_t magic;
#define MAGIC "/usr/share/file/magic"
#define MAGIC_WIDTH	16
#endif

char START_PATH[PATH_MAX];
char CONFIG_PATH[PATH_MAX];
// test globals
int ScanDepth = 10;
int filecount = 0;
int filesprocessed = 0;
int UseSSN = 1;
int UseVMCD = 0;
int UseAMEX = 0;
int Encrypt = 0;
int LogSyslog = 0;
int LOG_FAC = LOG_LOCAL0;
int Recurse = 1;
int CSVLog = 1;
int LogStdout = 0;
int LogAttributes = LOG_PATH|LOG_SIZE|LOG_REGEX;
int READ_DEPTH = 0;
int AppendLog = 0;
int Log2File = 0;
int Validator = 0;
int Minimize = 0;
int WhenDone = 0;
int PreserveAtime = 0;
int FollowSymlinks = 1;
int CaseSensPath = 0;  // 0 = case sensitive matching; 1 = case insensitive
char MaxgroupPath[PATH_MAX];
char LogPath[PATH_MAX];
char CustomLogPath[PATH_MAX];
char hit[129]; // 128-char regex fragment
char frag[129]; // 128-char match fragment
char LogFooter[128]; // 128-char log footer
int TotalMatches = 0;
int ScoreMatches = 0;
int LogTotalMatches = 0;
char ConfPath[PATH_MAX];
float Score = 0;
time_t spider_start;
time_t spider_end;
int fp;
unsigned char KEY[16];
unsigned char IV[8];
char Password[128];

int options = PCRE_NO_UTF8_CHECK;
FILE *logfp;

pid_t worker;

struct regstruct *startregp = NULL;

extern int optind;
extern char *optarg;

int verbose = 0;

int main(int argc, char **argv) {

	int c;

	bzero(CONFIG_PATH, PATH_MAX);

	while ((c = getopt(argc,argv, "vf:")) != EOF) {
		switch (c) {
			case 'f':
				snprintf(CONFIG_PATH, PATH_MAX, "%s", optarg);
				break;
			case 'v':
				verbose = 1;
				break;
			case '?':
				fprintf(stderr,"Invalid argument\n");
				exit(1);
		}
	}

	read_config();
#ifdef HAVE_LIBMAGIC
	load_magic();
#endif
	load_regexes();

	pcre_callout = pcre_callout_spider;

	umask(077);

	compile_regexes();

	if (Encrypt) {
		// do we have a password?
		if (!strlen(Password)) {
			fprintf(stderr, "No password supplied\n");
			exit(1);
		}
		// prep the log array
		startlog = (struct logarray *)malloc(sizeof(struct logarray));
		if (startlog == NULL) {
			fprintf(stderr, "Malloc: %s\n", strerror(errno));
			exit(1);
		}
		bzero(startlog -> entry, LOG_MAX);
		currlog = startlog;
		// prep our keying material
		generate_iv();
		generate_key();
	}

	if (Log2File && !LogStdout) {
		// get our filehandle open
		if (AppendLog) {
			if (CustomLogPath[0]) {
				logfp = fopen(CustomLogPath, "a+");
			} else {
				logfp = fopen(LogPath, "a+");
			}
		} else {
			if (CustomLogPath[0]) {
				logfp = fopen(CustomLogPath, "w");
			} else {
				logfp = fopen(LogPath, "w");
			}
		}
		if (logfp == NULL) {
			fprintf(stderr, "unable to open %s:%s\n",
					LogPath,
					strerror(errno));
			exit(1);
		}
	}

	if (LogSyslog) {
		(void)openlog("spider", LOG_PID|LOG_NDELAY, LOG_FAC);
	}

	
	// normally, this would run as a child process
	// we'd hold the child PID in pid_t worker
	// when the Stop Spider button is clicked, 
	// we'll send a TERM signal to the child process
	//
	run_spider(START_PATH);

	if (LogFooter[0]) {
		write_footer();
	}

	if (Encrypt) {
		// write out the encrypted log
		if (!spider_encrypt()) {
			fprintf(stderr, "failure to write encrypted log!\n");
			exit(1);
		}
	}

	if (logfp) { fclose(logfp); }

	if (WhenDone == EXIT_WHEN_DONE) {
		if (verbose) {
			fprintf(stderr, "Normal exit.\n");
		}
		exit(0);
	}
	if (WhenDone == RESTORE_WHEN_DONE) {
		// GTK fru-fru
	}
	if (WhenDone == VIEWLOG_WHEN_DONE) {
		// launch the log viewer
	}

	exit(0);
}

#ifdef HAVE_LIBMAGIC
void load_magic(void) {
	
	magic = magic_open(magic_flags);
	
	if (magic == NULL) {
		fprintf(stderr, "magic_open failed: %s\n", magic_error(magic));
		exit(1);
	}

	if (magic_load(magic, NULL) < 0) {
		fprintf(stderr, "magic_load failed: %s\n", magic_error(magic));
		exit(1);
	}

	return;
}
#endif

void load_regexes(void) {
	//
	// we'll populate the regex structs
	// with locally defined regexes
	//
	//
	struct regstruct *p;

	p = startregp;

	while (p) {
		p -> Pcre = pcre_compile(p -> regtext,
		                            options,
		                            &p -> error,
		                            &p -> erroffset,
		                            NULL
		                            );
		  // ought to test this; invalid regexes we should 
		  // prune from the linked list
		if (p -> Pcre == NULL) {
			fprintf(stderr, "regex compile error on pattern %s\n",
					p -> regtext);
			exit(1);
		}
		p -> pe = pcre_study(p -> Pcre,
		                       0,
		                       &p -> error);

		p = p -> next;
	}


	return;
}

void compile_regexes(void) {
	// here's where we compile the regexes we store natively as
	// well as the ones we've been passed as optional
//	const char *ssn_regex = "\\D\\d{3}-\\d{2}-\\d{4}\\D(?C)";
	const char *ssn_regex = "(?<!(\\w|-))(?!000)(?!666)([0-6]\\d\\d|7[01256]\\d|73[0123]|77[012])([-]?)(?!00)(\\d{2})\\3(?!0000)(\\d{4})(?!(\\w|\\-))(?C)";
	const char *vmcd_regex = "\\D\\d{4}-\\d{4}-\\d{4}-\\d{4}\\D(?C)";
	const char *amex_regex = "\\D\\d{4}-\\d{4}-\\d{4}-\\d{3}\\D(?C)";

	reSSN.next = NULL;
	reVMCD.next = NULL;
	reAMEX.next = NULL;

	if (UseSSN) {
	reSSN.Pcre = pcre_compile(ssn_regex,
                             options,
                             &reSSN.error,
                             &reSSN.erroffset,
                             NULL
                             );

	reSSN.pe = pcre_study(reSSN.Pcre,
				0,
				&reSSN.error);
	}

	if (UseVMCD) {
	reVMCD.Pcre = pcre_compile(vmcd_regex,
			options,
			&reVMCD.error,
			&reVMCD.erroffset,
			NULL
			);

	reVMCD.pe = pcre_study(reVMCD.Pcre,
				0,
				&reVMCD.error);
	}
	
	if (UseAMEX) {
	reAMEX.Pcre = pcre_compile(amex_regex,
			options,
			&reAMEX.error,
			&reAMEX.erroffset,
			NULL
			);

	reAMEX.pe = pcre_study(reAMEX.Pcre,
				0,
				&reAMEX.error);
	}

	return;
}

void run_spider(char *pPath) {
	// step 1, acquire targets
	// step 2, scan them
	//

	// GTK change the Run Spider button to a Stop Spider button
	//

	time(&spider_start);

	acquire_paths(pPath, Recurse);

	time(&spider_end);

	return;
}

void scan(char *pPath) {
	char buf[BUF_SIZE];	
	int nRead;
	off_t depth = 0;
	int ret = 0;
	struct skippaths *sp;
	int status = 0;
#ifdef HAVE_LIBMAGIC
	const char *type;
	struct skiptypes *p;
#else
	char extension[PATH_MAX];
#endif

	// check to see if we've got a skippath that matches the path
	// we've been passed.  if so, bail
	sp = startskippath;
	while (sp) {
		if (sp -> wildcards) {
			// regex match
			status = regexec(&sp -> skip2regex, pPath, (size_t) 0, NULL, 0);
			if (status == 0) {
				if (verbose) {
					fprintf(stderr,"skipping %s\n", pPath);
				}
				return;
			}
		} else {
			if (strstr(pPath, sp -> skippath)) {
				return;
			}
		}
		sp = sp -> next;
	}

	TotalMatches = 0;
	ScoreMatches = 0;
	if (verbose) {
		fprintf(stderr,"scanning %s\n", pPath);
	}
	// GTK update the progress label

	// various extension (yak!) specific bailouts
	// .gz or .tgz are delegated to zlib
	// .bz or .bz2 are delegated to bzip2
	// .zip gets delegated to the unzip library
	//
	// bzero(extension, PATH_MAX);
#ifndef HAVE_LIBMAGIC
	get_ext(pPath, extension);

	if (!strcasecmp(extension, "tgz") || !strcasecmp(extension, "gz")) {
		process_zlib(pPath);
		return;
	}

	if (!strcasecmp(extension, "bz2") || !strcasecmp(extension, "bz")) {
		process_bzip2(pPath);
		return;
	}

	if (!strcasecmp(extension, "zip")) {
		process_zip(pPath);
		return;
	}
	if (!strcasecmp(extension, "docx")) {
		process_zip(pPath);
		return;
	}
	if (!strcasecmp(extension, "xlsx")) {
		process_zip(pPath);
		return;
	}
	if (!strcasecmp(extension, "ods")) {
		process_zip(pPath);
		return;
	}
	if (!strcasecmp(extension, "odt")) {
		process_zip(pPath);
		return;
	}
	if (!strcasecmp(extension, "mbx")) {
		process_mbx(pPath);
		return;
	}
#else
	type = magic_file(magic,pPath);
	if (type) {
		p = startskip;
		while (p) {
			if (strstr(type, p -> type)) {
				if (verbose) {
					fprintf(stderr,"skipping %s\n", p -> type);
				}
				return;
			}
			p = p -> next;
		}
		if (strstr(type, "bzip2")) {
			process_bzip2(pPath);
			return;
		}
		if (strstr(type, "gzip")) {
			process_zlib(pPath);
			return;
		}
		if(strstr(type, "Zip")) {
			if (!strstr(type, "encrypt")) {
				process_zip(pPath);
			}
			return;
		}
		if (strstr(type, "ASCII mail text")) {
			process_mbx(pPath);
			return;
		}
		if (strstr(type, "RFC 822")) {
			process_mbx(pPath);
			return;
		}
		if (strstr(type, "RFC822")) {
			process_mbx(pPath);
			return;
		}
	}
#endif

	fp = open(pPath, O_RDONLY | O_NONBLOCK);

	if (fp < 0) {
		// don't much care why
#ifdef DEBUG
		fprintf(stderr, "file open failure: %s %s BAIL\n", 
				strerror(errno),
				pPath);
#endif
		return;
	}

	// read the file
	while ((nRead = read(fp, &buf, READ_DEPTH)) > 0) {
		if (is_match(buf,nRead)) {
			ret = 1;
			if (!LogTotalMatches) {
				send_match(hit,pPath);
				close(fp);
				return;
			}
		}
		bzero(buf, sizeof(buf));
		if (ScanDepth != 0) {
			depth += nRead;
		 	if (depth >= (ScanDepth * 1024)) {
				break;
			}
		}
	}

	if ((LogTotalMatches && TotalMatches) || ret) {
		send_match(hit, pPath);
	}

	close(fp);

	return;
}

int is_match(char *to_match, int readSize) {
	// returns 1 for a match, 0 for a miss
	int status;
	struct regstruct *regp;

	bzero(hit, 129);
	bzero(frag, 129);

	Validator = 0;

	if (UseSSN) {
		Validator = VALIDATOR_SSN;
		status = pcre_exec(reSSN.Pcre,
				reSSN.pe,
				to_match,
				readSize,
				0,
				0,
				reSSN.ovector,
				OVECCOUNT);
		if ((status >= 0) || (LogTotalMatches && TotalMatches)) {
			sprintf(hit, "SSN");
			return (1);
		}
	}

	if (UseVMCD) {
		Validator = VALIDATOR_LUHN;
		status = pcre_exec(reVMCD.Pcre,
				NULL,
				to_match,
				readSize,
				0,
				0,
				reVMCD.ovector,
				OVECCOUNT);
	
		if ((status >= 0) || (LogTotalMatches && TotalMatches)) {
			sprintf(hit, "VMCD");
			return (1);
		}
	}

	if (UseAMEX) {
		Validator = VALIDATOR_LUHN;
		status = pcre_exec(reAMEX.Pcre,
				NULL,
				to_match,
				readSize,
				0,
				0,
				reAMEX.ovector,
				OVECCOUNT);
	
		if ((status >= 0) || (LogTotalMatches && TotalMatches)) {
			sprintf(hit, "AMEX");
			return (1);
		}
	}

	Validator = 0;

	if (startregp) {
		regp = startregp;
		while (regp != NULL) {
			// try the match
			status = pcre_exec(regp -> Pcre,
					NULL,
					to_match,
					readSize,
					0,
					0,
					regp -> ovector,
					OVECCOUNT);
			if ((status >= 0) || (LogTotalMatches && TotalMatches)) {
				sprintf(hit, "%s", regp -> regtext);
				return(1);
			}
			regp = regp -> next;
		}
	}

	return (0);
}

void acquire_paths(char *startpath, int rec) {
	DIR *food; // that's foo-d
	struct dirent *dent;
	char tmp_path[PATH_MAX];
	struct skippaths *p;
	int status = 0;
	int follow = 0;
#ifdef HAVE_SYS_STAT
	struct stat sta;
	struct stat sta2;
#endif

	//
	// start reading in file names at startpath
	// anything that's a file, add to the linked list
	// if it's a directory, recurse if rec is set

	// check to see if we've got a skippath that matches the path
	// we've been passed.  if so, bail
	p = startskippath;

	while (p) {
		if (p -> wildcards) {
			// regex match
			status = regexec(&p -> skip2regex, startpath, (size_t) 0, NULL, 0);
			if (status == 0) {
				if (verbose) {
					fprintf(stderr,"skipping %s\n", startpath);
				}
				return;
			}
		} else {
			if (strstr(startpath, p -> skippath)) {
				return;
			}
		}
		p = p -> next;
	}

	food = opendir(startpath);

	if (food == NULL) {
#ifdef DEBUG
		fprintf(stderr, "opendir: %s\n", strerror(errno));
		fprintf(stderr, "path: %s\n", startpath);
#endif
		return;
	}

	while ((dent = readdir(food))) {
		snprintf(tmp_path, PATH_MAX, "%s/%s",
				startpath,
				dent -> d_name);
#ifndef HAVE_SYS_STAT
		if (dent -> d_type == DT_REG) {
#else
		if (lstat(tmp_path, &sta) < 0) {
			// error
			continue;
		}
		if (stat(tmp_path, &sta2) < 0) {
			// error
			continue;
		}
		if ((sta.st_mode & S_IFMT) == S_IFLNK) {
			follow = FollowSymlinks;
			if (verbose) {
				if (follow) {
					fprintf(stderr, "Following ");
				} else {
					fprintf(stderr, "Skipping ");
				}
				fprintf(stderr, "Symlink: %s\n", tmp_path);
			}
		} else {
			follow = 1;
		}

		if ((((sta2.st_mode & S_IFMT) == S_IFREG) && follow)) {
#endif
			scan(tmp_path);
			filecount++;
#ifdef HAVE_SYS_STAT
			if (PreserveAtime) {
				if (verbose) {
					fprintf(stderr, "Resetting atime on: %s\n", tmp_path);
				}
				struct timeval  utsbuf[2];
				bzero(&utsbuf[0], sizeof(struct timeval));
				bzero(&utsbuf[1], sizeof(struct timeval));
				utsbuf[0].tv_sec = sta.st_atime;
				utsbuf[1].tv_sec = sta.st_mtime;
				if (utimes(tmp_path, utsbuf)  < 0) {
					if (verbose) {
						fprintf(stderr, "Error restting atime: %s\n", strerror(errno));
					}
				}
			}
#endif
#ifndef HAVE_SYS_STAT
		} else if (dent -> d_type == DT_DIR) {
#else
		} else if (((sta2.st_mode & S_IFMT) == S_IFDIR) && follow) {
#endif
			if (strcmp(dent -> d_name, ".") && strcmp(dent -> d_name, "..")) {
				if (rec) {
					bzero(tmp_path, PATH_MAX);
					snprintf(tmp_path, PATH_MAX, "%s/%s",
							startpath,
							dent -> d_name);
					acquire_paths(tmp_path, rec);
				}
			}
		} else {
			// other file types
			// do we follow symlinks?
		}
#ifdef HAVE_SYS_STAT
//		free(&sta);
#endif
	}

	closedir(food);

	return;
}

void send_match(char *rehit, char *pPath) {
	// we'll have options for sending to syslog
	// writing a log file
	// writing an encrypted log file
	char msg[256];

	// if we're syslogging, we'll create a basic message based
	// on what we know now.
	snprintf(msg, 256, "%s %s\n", pPath, rehit);
	// otherwise, this function will delegate to write_log 
	// where the real work will happen

	if (LogSyslog) {
		syslog(LOG_NOTICE, "%s", msg);
	}

	if (strlen(LogPath)) {
		// " " until we have a true frag
		write_log(rehit, " ", pPath);
	}

	return;
}

void write_log(char *regex, char *frag, char *pPath) {
	struct logarray *p;
	char msg[2048];

	bzero(msg, 2048);
	// craft our log message
	if (CSVLog) {
		// craft a CSV line
		craft_csv_entry(msg, pPath, regex, frag);
	} else {
		// craft a basic line
		snprintf(msg, 2048, "Match: %s %s %s\n",
				pPath,
				hit,
				regex);
	}

	// write

	if (Encrypt) {
		// cache the results in the log array
		snprintf(currlog -> entry, LOG_MAX, "%s",
				msg);
		p = (struct logarray *)malloc(sizeof(struct logarray));
		if (p == NULL) {
			return;
		}
		currlog -> next = p;
		p -> next = NULL;
		bzero(p -> entry, LOG_MAX);
		currlog = p;
		return;
	} else {
		if (LogStdout) {
			fprintf(stdout, "%s", msg);
			(void)fflush(stdout);
		} else {
			fprintf(logfp, "%s", msg);
			fflush(logfp);
		}
	}

	return;

}

void read_config(void) {
	// our config file search path:
	// CUR_USER/.spider/spider.conf
	// /root/.spider/spider.conf
	// /etc/spider/spider.conf
	struct passwd *pwd;
	char path_buf[PATH_MAX];
  char path_buf2[PATH_MAX];
	FILE *fp;
	char config_buf[4096];
	char s1[4096];
	char s2[4096];
	struct regstruct *cregp;
	struct regstruct *tregp;
	struct skiptypes *cskip;
	struct skiptypes *tskip;
	struct skippaths *cskipp;
	struct skippaths *tskipp;
	int first_regex = 1;
	int first_skip = 1;
	int first_skipp = 1;

	pwd = getpwuid(getuid());

	cregp = startregp;
	cskip = startskip;
	cskipp = startskippath;

	snprintf(path_buf, PATH_MAX, "%s/.spider/%s", pwd -> pw_dir, CONFIG_NAME);
  snprintf(path_buf2, PATH_MAX, "%s/etc/spider/spider.conf", PREFIX);

	bzero(pwd, sizeof(struct passwd));
	bzero(LogFooter, sizeof(LogFooter));
	bzero(Password, sizeof(Password));

	if (CONFIG_PATH[0]) {
		if (verbose) {
			fprintf(stderr, "Trying: %s\n", CONFIG_PATH);
		}
		fp = fopen(CONFIG_PATH, "r");
	} else {
		if (verbose) {
			fprintf(stderr, "Trying: %s\n", path_buf);
		}
		fp = fopen(path_buf, "r");
	} 

	if (fp == NULL) {
		// different path
		fp = fopen("/root/.spider/spider.conf", "r");
		if (fp == NULL) {
			// one last try
			fp = fopen(path_buf2, "r");
			if (fp == NULL) {
				fprintf(stderr, "No config file!\n");
				exit(1);
			} else {
				snprintf(ConfPath, PATH_MAX, "%s", path_buf);
			}
		} else {
			snprintf(ConfPath, PATH_MAX, "%s", path_buf);
		}
	} else {
		snprintf(ConfPath, PATH_MAX, "%s", path_buf);
	}

	// if we fall through to here, we're reading something
	while (fgets(config_buf, 4096, fp) != NULL) {
		if (strncmp(config_buf, "#", 1) && 
				strncmp(config_buf, "\n", 1)){

//			if (sscanf(config_buf, "%s %[ 0-9a-zA-Z:,\\/{($^)}.%]", s1, s2)	== 2) {	
			if (sscanf(config_buf, "%s %[ !-~]", s1, s2)	== 2) {	
				if (!strcasecmp(s1, "recurse")) {
					Recurse = atoi(s2);
				}
				if (!strcasecmp(s1, "preserveatime")) {
					PreserveAtime = atoi(s2);
				}
				if (!strcasecmp(s1, "followsymlinks")) {
					FollowSymlinks = atoi(s2);
				}
				if (!strcasecmp(s1, "logstdout")) {
					LogStdout = atoi(s2);
				}
				if (!strcasecmp(s1, "scandepth")) {
					ScanDepth = atoi(s2);
				}
				if (!strcasecmp(s1, "usessn")) {
					UseSSN = atoi(s2);
				}
				if (!strcasecmp(s1, "usevmcd")) {
					UseVMCD = atoi(s2);
				}
				if (!strcasecmp(s1, "useamex")) {
					UseAMEX = atoi(s2);
				}
				if (!strcasecmp(s1, "casesenspath")) {
					CaseSensPath = atoi(s2);
				}
				if (!strcasecmp(s1, "encrypt")) {
					Encrypt = atoi(s2);
				}
				if (!strcasecmp(s1, "password")) {
					snprintf(Password, 128, "%s", s2);
				}
				if (!strcasecmp(s1, "logsyslog")) {
					LogSyslog = atoi(s2);
				}
				if (!strcasecmp(s1, "logfac")) {
					// figure things out
					set_fac(s2);
				}
				if (!strcasecmp(s1, "minimize")) {
					Minimize = atoi(s2);
				}
				if (!strcasecmp(s1, "whendone")) {
					WhenDone = atoi(s2);
				}
				if (!strcasecmp(s1, "maxgroups")) {
					snprintf(MaxgroupPath, PATH_MAX,
							"%s", s2);
				}
				if (!strcasecmp(s1, "log2file")) {
					Log2File = atoi(s2);
				}
				if (!strcasecmp(s1, "startdir")) {
					snprintf(START_PATH, PATH_MAX,
							"%s", s2);
				}
				if (!strcasecmp(s1, "appendlog")) {
					AppendLog = atoi(s2);
				}
				if (!strcasecmp(s1, "csvlog")) {
					CSVLog = atoi(s2);
				}
				if (!strcasecmp(s1, "logattributes")) {
					LogAttributes = atoi(s2);
				}
				if (!strcasecmp(s1, "logpath")) {
					snprintf(LogPath, PATH_MAX, "%s", s2);
				}
				if (!strcasecmp(s1, "logtotalmatches")) {
					LogTotalMatches = atoi(s2);
				}
				if (!strcasecmp(s1, "logfooter")) {
					snprintf(LogFooter, 128, "%s", s2);
				}
				if (!strcasecmp(s1, "regex")) {
					// add this to the end of the regex
					// linked list
					if (!cregp) {
						tregp = (struct regstruct *)
							malloc(sizeof(struct regstruct));
						if (tregp == NULL) {
							fprintf(stderr, "malloc! %s\n", strerror(errno));
							exit(1);
						}
						tregp -> next = NULL;
						cregp = tregp;
						if (first_regex) { 
							startregp = cregp;
							first_regex = 0;
						}
					} else {
						// chain another
						tregp = (struct regstruct *)
							malloc(sizeof(struct regstruct));
						if (tregp == NULL) {
							fprintf(stderr, "malloc!%s\n", strerror(errno));
							exit(1);
						}
						tregp -> next = NULL;
						cregp -> next = tregp;
						cregp = tregp;
					}
					if (!strstr(s2, "(C?)")) {
						strncat(s2, "(C?)", 4);
					}
					snprintf(cregp -> regtext, 256, "%s", s2);
			 	}
				if (!strcasecmp(s1, "skiptype")) {
					// add this to the linked list of 
					// skip types
					if (!cskip) {
						tskip = (struct skiptypes *)
							malloc(sizeof(struct skiptypes));
						if (tskip == NULL) {
							fprintf(stderr, "malloc!%s\n", strerror(errno));
							exit(1);
						}
						tskip -> next = NULL;
						cskip = tskip;
						if (first_skip) {
							startskip = cskip;
							first_skip = 0;
						}
					} else {
						tskip = (struct skiptypes *)
							malloc(sizeof(struct skiptypes));
						if (tskip == NULL) {
							fprintf(stderr,"malloc! %s\n", strerror(errno));
							exit(1);
						}
						tskip -> next = NULL;
						cskip -> next = tskip;
						cskip = tskip;

					}
					snprintf(cskip -> type, 128, "%s", s2);
				}
				if (!strcasecmp(s1, "skippath")) {
					if (!cskipp) {
						tskipp = (struct skippaths *)
							malloc(sizeof(struct skippaths));
						if (tskipp == NULL) {
							fprintf(stderr, "malloc!%s\n", strerror(errno));
							exit(1);
						}
						tskipp -> next = NULL;
						cskipp = tskipp;
						if (first_skipp) {
							startskippath = cskipp;
							first_skipp = 0;
						}
					} else {
						tskipp = (struct skippaths *)
							malloc(sizeof(struct skippaths));
						if (tskipp == NULL) {
							fprintf(stderr, "malloc!%s\n", strerror(errno));
							exit(1);
						}
						tskipp -> next = NULL;
						cskipp -> next = tskipp;
						cskipp = tskipp;
					}
					snprintf(cskipp -> skippath, PATH_MAX, "%s", s2);
				}
			}
		}
	} // end while

	fclose(fp);
	// sanity check
	//
	sanity_check();

	// now that we're done with that, set a couple of globals
	set_globals();

	return;

}

void set_globals(void) {
	float depth;
	int exp;

	if (ScanDepth == 0) {
		READ_DEPTH = BUF_SIZE;
	} else {
		depth = (float)(ScanDepth * 1024);	
		exp = (int)(log(depth)/log(2)) + 1;
		READ_DEPTH = (int)pow(2, (float)exp);
		if (READ_DEPTH > BUF_SIZE) {
			READ_DEPTH = BUF_SIZE;
		}
	}

	bzero(CustomLogPath, PATH_MAX);

	if (strstr(LogPath, "%")) {
		make_custom_log_path();	
	}

	read_maxgroups(MaxgroupPath);

	// we'll also fix up the skippaths globs
	set_globs();

	return;

}

void set_fac(char *logfac) {
	int localnum;
	char *cp;
	// 
	cp = logfac;
	cp += strlen("local");
	localnum = atoi(cp);
	LOG_FAC = ((16 + localnum)<<3);

	return;
}

void sig_child_handler(int sig) {
	/* basically:
	 * HUP: die
	 * INT: die
	 * TERM: die
	 * USR1: skip current file
	 * USR2: checkpoint at current file and exit
	 * */

	if (sig == SIGHUP || sig == SIGTERM || sig == SIGINT) {
		exit(0);
	}

	// USR1, close current file
	if (sig == SIGUSR1) {
		if (fp > 0) { close(fp); }
		//
	}

	if (sig == SIGUSR2) {
	// not anymore
	} // USR2

	return;
}

void sig_handler(int sig) {
	/* basically:
	 * HUP: re-read config file
	 * INT: die
	 * TERM: die
	 * everything else: ignore */
	if (sig == SIGHUP) {
		read_config();
		set_globals();
	}

	if (sig == SIGINT || sig == SIGTERM) {
		exit(0);
	}

	return;
}

void craft_csv_entry(char *csventry, char *pPath, char *regex, char *hit) {
	/* we'll do two things:
	 * make nice-nice CSV with the path
	 * stuff
	 * we'll also craft a CSV entry based on the LogAttributes mask
	 * set by the user */
	char entry[2048];
	char tmp_buf[128];
	char tmp_path[PATH_MAX];
	struct stat sta;
	struct tm *mytime;
	char *cp;
	MD5_CTX md5c;
	unsigned char md5[MD5_DIGEST_LENGTH];
	char buf[BUF_SIZE];
	int fd;
	int nRead;
	int i;
	const char *type;

	bzero(entry, 2048);

	if ((LogAttributes & LOG_SCORE) && (LogAttributes & LOG_NONZERO_SCORE)) {
		if (ScoreMatches == 0) { return; }
	}

	if (LogAttributes & LOG_PATH) {
		if (strstr(pPath, "\"") || strstr(pPath, ",")) {
			cp = pPath;
			bzero(tmp_path, PATH_MAX);
			strncat(tmp_path, "\"", 1);
			while (*cp != '\0') {
				if (*cp == '"') {
					strncat(tmp_path, "\"\"", 2);
				} else {
					strncat(tmp_path, cp, 1);
				}
				cp++;
			}
			strncat(tmp_path, "\"", 1);
			strncat(entry, tmp_path, strlen(tmp_path));
			strncat(entry, ",", 1);
		} else {
			strncat(entry, pPath, strlen(pPath));
			strncat(entry, ",", 1);
		}
	}	

	if (LogAttributes & LOG_HASH) {
		// grab an MD5 of the file
		MD5_Init(&md5c);
		fd = open(pPath, O_RDONLY);
		if (fd < 0) {
			strncat(entry, "NA,", 3);
		} else {
			while ((nRead = read(fd, &buf, BUF_SIZE)) > 0) {
				MD5_Update(&md5c, buf, nRead); 
			}
			close(fd);
			MD5_Final(&(md5[0]), &md5c);
			for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
				snprintf(tmp_buf,  128, "%02x", md5[i]);
				strncat(entry, tmp_buf, strlen(tmp_buf));
			}
			strncat(entry, ",", 1);
		}
	}

	if (LogAttributes & LOG_TYPE) {
		// presupposes compilation with libmagic
		//
#ifndef HAVE_LIBMAGIC
		strncat(entry, "File,", 5);
#else
		// grab the magic type and stuff the first MAGIC_WIDTH characters 
		// in here

		type = magic_file(magic, pPath);
		if (type == NULL) {
			sprintf(tmp_buf, "unknown");
		} else {
			snprintf(tmp_buf, MAGIC_WIDTH, "%s", type);
			cp = &tmp_buf[0];
			while (*cp != '\0') {
				if (*cp == '\"') {
					*cp = '.';
				}
				if (*cp == ',') {
					*cp = '.';
				}
				cp++;
			}
		}
		strncat(entry, tmp_buf, strlen(tmp_buf));
		strncat(entry, ",", 1);
#endif
	}

	if (stat(pPath, &sta) != 0) {
		return;
	}

	if (LogAttributes & LOG_OWNUID) {
		bzero(tmp_buf, 128);
		snprintf(tmp_buf, 128, "%d,", sta.st_uid);
		strncat(entry, tmp_buf, strlen(tmp_buf));
	}

	if (LogAttributes & LOG_SIZE) {
		bzero(tmp_buf, 128);
		snprintf(tmp_buf, 128, "%lld,", sta.st_size);
		strncat(entry, tmp_buf, strlen(tmp_buf));
	}


	// ctime, atime, mtime are all in human readable, GMT
	//

	if (LogAttributes & LOG_CTIME) {
		bzero(tmp_buf, 128);
		mytime = gmtime(&sta.st_ctime);
		strftime(tmp_buf, 128, "%F %H:%M:%S,", mytime);
		strncat(entry, tmp_buf, strlen(tmp_buf));
	}

	if (LogAttributes & LOG_ATIME) {
	        bzero(tmp_buf, 128);
	        mytime = gmtime(&sta.st_atime);
	        strftime(tmp_buf, 128, "%F %H:%M:%S,", mytime);
	        strncat(entry, tmp_buf, strlen(tmp_buf));
	}

	if (LogAttributes & LOG_MTIME) {
		bzero(tmp_buf, 128);
		mytime = gmtime(&sta.st_mtime);
		strftime(tmp_buf, 128, "%F %H:%M:%S,", mytime);
		strncat(entry, tmp_buf, strlen(tmp_buf));
	}

	if (LogAttributes & LOG_HOSTNAME) {
		bzero(tmp_buf, 128);
		if (gethostname(tmp_buf, 128) != 0) {
			sprintf(tmp_buf, "NA,");
		}
		strncat(entry, tmp_buf, strlen(tmp_buf));
		strncat(entry, ",", 1);
	}

	// we have left: regex, match fragment, total matches, score
	if (LogAttributes & LOG_REGEX) {
		strncat(entry, regex, strlen(regex));
		strncat(entry, ",", 1);
	}

	// the fragment was properly comma and quote sanitized when it was 
	// generated

	if (LogAttributes & LOG_MATCH) {
		strncat(entry, frag, strlen(frag));
		strncat(entry, ",", 1);
	}

	if (LogAttributes & LOG_TOTM) {
		bzero(tmp_buf, 128);
		snprintf(tmp_buf, 128, "%d,", TotalMatches);
		strncat(entry, tmp_buf, strlen(tmp_buf));
	}
	if (LogAttributes & LOG_SCORE) {
		if (TotalMatches) {
			Score = (float)ScoreMatches/TotalMatches;
		} else {
			Score = 0.0;
		}
		bzero(tmp_buf, 128);
		snprintf(tmp_buf, 128, "%.2f,", Score);
		strncat(entry, tmp_buf, strlen(tmp_buf));
	}
	if (entry[strlen(entry) - 1] == ',') {
		entry[strlen(entry) - 1] = '\n';
	}

	bzero(csventry, 2048);
	snprintf(csventry, 2048, "%s", entry);

	return;

}

void save_config(char *confpath) {
	FILE *fp;
	char *cp;
	// we'll open the config file spider currently has in use
	// get an exclusive lock, truncate the file, then write out
	// our current config
	struct regstruct *p;
	struct skiptypes *sp;
	struct skippaths *spp;

	fp = fopen(confpath, "w");

	if (fp == NULL) {
		fprintf(stderr, "unable to open %s\n", confpath);
		return;
	}

#ifndef HAVE_FLOCK
	if (flock(fileno(fp), LOCK_EX | LOCK_NB) < 0) {
		fprintf(stderr, "unable to lock %s\n", confpath);
		return;
	}
#else
	if (lockf(fileno(fp), F_LOCK, 0) < 0) {
		fprintf(stderr, "unable to lock %s: %s\n",
			confpath,
			strerror(errno));
		return;
	}
#endif 

	if (ftruncate(fileno(fp), 0) < 0) {
		fprintf(stderr, "unable to truncate %s\n", confpath);
		return;
	}

	// start writing
	fprintf(fp, "# do not edit this file by hand.  changes may be lost\n");
	fprintf(fp, "scandepth %d\n", ScanDepth);
	fprintf(fp, "usessn %d\n", UseSSN);
	fprintf(fp, "usevmcd %d\n", UseVMCD);
	fprintf(fp, "useamex %d\n", UseAMEX);
	fprintf(fp, "encrypt %d\n", Encrypt);
	fprintf(fp, "logsyslog %d\n", LogSyslog);
	fprintf(fp, "logstdout %d\n", LogStdout);
	// log facility
	switch(LOG_FAC) {
		case LOG_LOCAL0:
			fprintf(fp, "logfac local0\n");
			break;
		case LOG_LOCAL1:
			fprintf(fp, "logfac local1\n");
			break;
		case LOG_LOCAL2:
			fprintf(fp, "logfac local2\n");
			break;
		case LOG_LOCAL3:
			fprintf(fp, "logfac local3\n");
			break;
		case LOG_LOCAL4:
			fprintf(fp, "logfac local4\n");
			break;
		case LOG_LOCAL5:
			fprintf(fp, "logfac local5\n");
			break;
		case LOG_LOCAL6:
			fprintf(fp, "logfac local6\n");
			break;
		case LOG_LOCAL7:
			fprintf(fp, "logfac local7\n");
			break;
	}
	fprintf(fp, "csvlog %d\n", CSVLog);
	fprintf(fp, "appendlog %d\n", AppendLog);
	fprintf(fp, "logattributes %d\n", LogAttributes);
	fprintf(fp, "logpath %s\n", LogPath);
	fprintf(fp, "log2file %d\n", Log2File);
	fprintf(fp, "logtotalmatches %d\n", LogTotalMatches);
	fprintf(fp, "startdir %s\n", START_PATH);	
	fprintf(fp, "recurse %d\n", Recurse);
	fprintf(fp, "minimize %d\n", Minimize);
	fprintf(fp, "whendone %d\n", WhenDone);

	p = startregp;
	while (p != NULL) {
		fprintf(fp, "regex %s\n", p -> regtext);
		p = p -> next;
	}

	sp = startskip;
	while (sp != NULL) {
		fprintf(fp, "skiptype %s\n", sp -> type);
		sp = sp -> next;
	}

	spp = startskippath;
	while (spp != NULL) {
		fprintf(fp, "skippath %s\n", spp -> skippath);
		spp = spp -> next;
	}

	cp = &LogFooter[0];

	if (cp) {
		fprintf(fp, "logfooter ");
		while (cp) {
			if (*cp == '\\') {
				fprintf(fp, "\\\\");
			} else {
				fprintf(fp, "%c", *cp);
			}
			cp++;
		}
	}


	fflush(fp);
#ifndef HAVE_FLOCK
	(void)flock(fileno(fp), LOCK_UN);
#else
	(void)lockf(fileno(fp), F_ULOCK, 0);
#endif
	fclose(fp);
	

	return;
}

int pcre_callout_spider(pcre_callout_block *block) {
	// bail immediately
	// if we're looking for frags, see what we've got
	const char *cp;
	char tmp_buf[MATCH_WIDTH];
	int startpos = 0;
	int runlen = 0;
	char matched[MATCH_WIDTH]; // we'll need this for validators
	int i;
	int valid = 0;

	cp = block -> subject;
	// cp += block -> start_match;
	if ((block -> start_match - (MATCH_WIDTH / 2)) < 0) {
		startpos = 0;
	} else {
		startpos = ((block -> start_match - (MATCH_WIDTH / 2)));
	}
	if ((startpos + MATCH_WIDTH) > block -> subject_length) {
		runlen = (MATCH_WIDTH - startpos) - 1;
	} else {
		runlen = MATCH_WIDTH;
	}

	if ((runlen < 0) || (runlen > MATCH_WIDTH)) {
		runlen = 0;
	}

	bzero(tmp_buf, MATCH_WIDTH);
	cp += startpos;
	strncat(tmp_buf, cp, runlen);
	sanitize_buf(tmp_buf);
	snprintf(frag, MATCH_WIDTH, "%s", tmp_buf);

	if (Validator && (Validator == VALIDATOR_SSN)) {
		// we *might* get away with a small bracket on the match
		// and ignoring any frag with ETag in it.
		if (strstr(frag, "ETag")) {
			return 1;
		}
	}

	// grab the match itself
	if (Validator) {
		bzero(matched, MATCH_WIDTH);
		cp = block -> subject;
		cp += block -> start_match;
		for (i = block -> start_match; i < block -> current_position; i++) {
			strncat(matched, cp, 1);
			cp++;
		}
		// send it to the validator for this regex
		if (Validator == VALIDATOR_SSN) {
			valid += validate_ssn(matched);
		} else if (Validator == VALIDATOR_LUHN) {
			valid += validate_luhn(matched);
		} else {
			// none
		}
	}

	ScoreMatches += valid;

/*	if (!valid) {
		// hmm.  we want matching to continue until we find a valid
		return 1;
	}
*/

	if (!LogTotalMatches) { return 0; }

	TotalMatches++;

	return 1;
}

void make_custom_log_path(void) {
	char *cp;
	char log_path[PATH_MAX];
	struct tm *tm_gmt;
	char foo[256];
	time_t now;
	struct passwd *pwd;
	// we'll walk through LogPath writing to CustomLogPath

	// we'll take the same basic args as WinSpider:
	// %d day of month, numeric
	// %D day of week, english
	// %P day of year, numeric
	// %m month, numeric
	// %M month, english
	// %y four digit year
	// %T time %H%M%S format
	// %N hostname
	// %u username running spider

	cp = &LogPath[0];

	// get our time
	time(&now);
	tm_gmt = gmtime(&now);
	
	for ( ; *cp; ++cp) {
		bzero(foo, sizeof(foo));
			if (*cp == '%') {
				switch (*++cp) {
					case '\0':
						--cp;
						break;
					case 'd':
						// day of week
						strftime(foo, sizeof(foo), "%d", tm_gmt);
						strncat(log_path, foo, strlen(foo));
						break;
					case 'D':
						// day of week, english
						strftime(foo, sizeof(foo), "%A", tm_gmt);
						strncat(log_path, foo, strlen(foo));
						break;
					case 'P':
						// day of year, numeric
						strftime(foo, sizeof(foo), "%j", tm_gmt);
						strncat(log_path, foo, strlen(foo));
						break;
					case 'm':
						// month, numeric
						strftime(foo, sizeof(foo), "%m", tm_gmt);
						strncat(log_path, foo, strlen(foo));
						break;
					case 'M':
						strftime(foo, sizeof(foo), "%b", tm_gmt);
						strncat(log_path, foo, strlen(foo));
						break;
					case 'y':
						// four digit year
						strftime(foo, sizeof(foo), "%Y", tm_gmt);
						strncat(log_path, foo, strlen(foo));
						break;
					case 'T':
						// time HHMMSS
						strftime(foo, sizeof(foo), "%H%M%S", tm_gmt);
						strncat(log_path, foo, strlen(foo));
						break;
					case 'N':
						// hostname
						if (gethostname(foo, sizeof(foo)) < 0) {
							// no hostname
							strncat(log_path, "NA", 2);
						} else {
							strncat(log_path, foo, strlen(foo));
						}
						break;
					case 'u':
						// username
						pwd = getpwuid(getuid());
						if (pwd == NULL) {
							strncat(log_path, "NA", 2);
						} else {
							snprintf(foo, sizeof(foo), "%s", pwd -> pw_name);
							strncat(log_path, foo, strlen(foo));
						}
						break;
					case '%':
					default:
						break;

				} // end switch

			} else {
				strncat(log_path, cp, 1);
			}
	} // end for

	snprintf(CustomLogPath, PATH_MAX, "%s", log_path);

	return;

}

void get_ext(char *pPath, char *ext) {
	// we'll grab the basename, then figure out the extension
	// from there
	char *base;
	char *cp;

	base = basename(pPath);
	if (!strstr(base, ".")) { 
		bzero(ext, PATH_MAX);
		return;
	}

	cp = strrchr(base, '.');
	cp++;
	snprintf(ext, PATH_MAX, "%s", cp);

	return;

}

void process_mbx(char *pPath) {
	/* we'll read the mailbox line by line, skipping mail headers by virtue of them
	 * starting with a "From " line and the header block ending with a blank line
	 * */
	char buf[BUF_SIZE];
	FILE *fp;
	int nRead;
	int ret = 0;
	long depth = 0;
	int header = 0;

	fp = fopen(pPath, "r");

	if (fp == NULL) {
		return;
	}

	bzero(buf, BUF_SIZE);

	while (fgets(buf, BUF_SIZE, fp)) {
		nRead = strlen(buf);
		depth += nRead;
		if (!strncmp(buf, "From ", 5)) {
			header = 1;
		}
		if (buf[0] == '\n') {
			header = 0;
		}
		if (! header) {
			// scan
			if (is_match(buf, nRead)) {
				ret = 1;
				if (!LogTotalMatches) {
					send_match(hit,pPath);
					fclose(fp);
					return;
				}
			}
			if ((ScanDepth != 0) && (depth >= (ScanDepth * 1024))) {
				break;
			}
		}
		bzero(buf, BUF_SIZE);
	}

	if ((LogTotalMatches && TotalMatches) || ret) {
		send_match(hit, pPath);
	}

	fclose(fp);

	return;
}

void process_zlib(char *pPath) {
#ifdef HAVE_LIBZ
	gzFile gzfile;
	char buf[BUF_SIZE];	
	int nRead;
	long depth = 0;
	int ret = 0;

	gzfile = gzopen(pPath, "rb");

	if (gzfile == NULL) {
		// don't care why
		return;
	}

	while ((nRead = gzread(gzfile, &buf, BUF_SIZE)) > 0) {
		depth += nRead;
		if (is_match(buf,nRead)) {
			ret = 1;
			if (!LogTotalMatches) {
				send_match(hit,pPath);
				(void)gzclose(gzfile);
				return;
			}
		}
		bzero(buf, sizeof(buf));
		if ((ScanDepth != 0) && (depth >= (ScanDepth * 1024))) {
			break;
		}
	}

	if ((LogTotalMatches && TotalMatches) || ret) {
		send_match(hit, pPath);
	}

	(void)gzclose(gzfile);
#endif
	return;
}

void process_bzip2(char *pPath) {
#ifdef HAVE_LIBBZ2
	BZFILE *bzfile;
	char buf[BUF_SIZE];	
	int nRead;
	long depth = 0;
	int ret = 0;

	bzfile = BZ2_bzopen(pPath, "rb");

	if (bzfile == NULL) {
		// don't care why
		return;
	}

	while ((nRead = BZ2_bzread(bzfile, &buf, BUF_SIZE)) > 0) {
		depth += nRead;
		if (is_match(buf,nRead)) {
			ret = 1;
			if (!LogTotalMatches) {
				send_match(hit,pPath);
				(void)BZ2_bzclose(bzfile);
				return;
			}
		}
		bzero(buf, sizeof(buf));
		if ((ScanDepth != 0) && (depth >= (ScanDepth * 1024))) {
			break;
		}
	}

	if ((LogTotalMatches && TotalMatches) || ret) {
		send_match(hit, pPath);
	}

	(void)BZ2_bzclose(bzfile);
#endif
	return;
}

void process_zip(char *pPath) {
#ifdef HAVE_LIBZZIP
	ZZIP_DIR *dir;
	ZZIP_FILE *fp;
	ZZIP_DIRENT dirent;
	char buf[BUF_SIZE];	
	int nRead;
	long depth = 0;
	int ret = 0;
	
	dir = zzip_dir_open(pPath, 0);

	if (!dir) { return; }

	while (zzip_dir_read(dir, &dirent)) {
		fp = zzip_file_open(dir, dirent.d_name, 0);
		if (fp) {
			// pull the data and scan
			while ((nRead = zzip_file_read(fp, buf, BUF_SIZE)) > 0) {
				depth += nRead;
				if (is_match(buf,nRead)) {
					ret = 1;
					if (!LogTotalMatches) {
						send_match(hit,pPath);
						break;
					}
				}
				bzero(buf, sizeof(buf));
				if ((ScanDepth != 0) && (depth >= (ScanDepth * 1024))) {
					break;
				}

			}
			zzip_file_close(fp);
		}
	}

	if ((LogTotalMatches && TotalMatches) || ret) {
		send_match(hit, pPath);
	}

	zzip_dir_close(dir);
#endif
	return;
}

void sanitize_buf(char *buf) {
	char *cp;

	cp = buf;

	while (*cp) {
		if (*cp == ',') {
			*cp = '.';
		} else if (*cp == '\"') {
			*cp = '.';
		} else if (((int)*cp >= 32) && ((int)*cp < 127)) {
			// do nothing
		} else {
			*cp = '.';
		}
		cp++;
	}

	return;
}

int validate_ssn(char *SSN) {
	char *cp;
	int area = 0;
	int group = 0;
	char tmp_buf[16];
	char agbuf[16];

	cp = SSN;

	bzero(tmp_buf, 16);
	bzero(agbuf, 16);

	while (*cp) {
		if (isdigit(*cp)) {
			strncat(tmp_buf, cp, 1);
		}
		cp++;
	}

	// tmp_buf should be the SSN itself
	if (!strncmp("393222000", tmp_buf, 9)) {
		return (0);
	}

	cp = &tmp_buf[0];
	strncat(agbuf, cp, 3);
	area = atoi(agbuf);
	cp += 3;
	bzero(agbuf, 16);
	strncat(agbuf, cp, 2);
	group = atoi(agbuf);

	if (area >= 900) {
		return (0);
	}

	if (maxgroup[area] <= 0) {
		return (0);
	}

	return(maxarea(maxgroup[area], group));

}

int maxarea(int alloc, int group) {
	int i = 1;
	int ret = 0;

	if (alloc == 99) {
		return (1);
	}

	while (i <= 9) {
		if (group == i) {
			ret = 1;
			return(ret);
		}
		if (i == alloc) {
			return(ret);
		}
		i += 2;
	}

	i = 10;

	while (i <= 98) {
		if (group == i) {
			ret = 1;
			return (ret);
		}
		if (i == alloc) {
			return (ret);
		}
		i += 2;
	}

	i = 2;

	while (i <= 8) {
		if (group == i) {
			ret = 1;
			return(ret);
		}
		if (i == alloc) {
			return (ret);
		}
		i += 2;
	}

	i = 11;

	while (i <= 99) {
		if (group == i) {
			ret = 1;
			return(ret);
		}
		if (i == alloc) {
			return(ret);
		}
		i += 2;
	}
		
	return (ret);
}

int validate_luhn(char *CCN) {
	char *cp;
	char tmp_buf[128];
	int start;
	int sum = 0;
	int i = 0;
	int twice;
	int number[128];
	int counter = 0;

	cp = CCN;
	bzero(tmp_buf, 128);

	while (*cp) {
		if (isdigit(*cp)) {
			strncat(tmp_buf, cp, 1);
			number[counter] = atoi(tmp_buf);
			bzero(tmp_buf, 128);
			counter++;
		}
		cp++;
	}

	start = strlen(tmp_buf) % 2;

	for (i = start; i < counter; i += 2) {
		twice = number[i] * 2;
		if (twice >= 10) {
			number[i] = twice - 9;
		} else {
			number[i] = twice;
		}
	}

	for (i = 0; i < counter; i++) {
		sum += number[i];
	}

	if (sum % 10) {
		return (0);
	} else {
		return (1);
	}


	return 1;
}

void write_footer(void) {
	// we'll take LogFooter, do the replaceable thing, then write it
	// to logfp
	// this is going to be a major reinvention of make_custom_log_path
	// we'll take more optional params:
	// %R: runtime
	// \r: CR
	// \n: LF
	char new_footer[256];
	char foo[256];
	char *cp;
	time_t now;
	struct tm *tm_gmt;
	struct passwd *pwd;
	struct logarray *p;

	cp = &LogFooter[0];

	bzero(new_footer, sizeof(new_footer));

	// get our time
	time(&now);
	tm_gmt = gmtime(&now);
	
	for ( ; *cp; ++cp) {
		bzero(foo, sizeof(foo));
			if (*cp == '%') {
				switch (*++cp) {
					case '\0':
						--cp;
						break;
					case 'd':
						// day of week
						strftime(foo, sizeof(foo), "%d", tm_gmt);
						strncat(new_footer, foo, strlen(foo));
						break;
					case 'D':
						// day of week, english
						strftime(foo, sizeof(foo), "%A", tm_gmt);
						strncat(new_footer, foo, strlen(foo));
						break;
					case 'P':
						// day of year, numeric
						strftime(foo, sizeof(foo), "%j", tm_gmt);
						strncat(new_footer, foo, strlen(foo));
						break;
					case 'm':
						// month, numeric
						strftime(foo, sizeof(foo), "%m", tm_gmt);
						strncat(new_footer, foo, strlen(foo));
						break;
					case 'M':
						strftime(foo, sizeof(foo), "%b", tm_gmt);
						strncat(new_footer, foo, strlen(foo));
						break;
					case 'y':
						// four digit year
						strftime(foo, sizeof(foo), "%Y", tm_gmt);
						strncat(new_footer, foo, strlen(foo));
						break;
					case 'T':
						// time HHMMSS
						strftime(foo, sizeof(foo), "%H%M%S", tm_gmt);
						strncat(new_footer, foo, strlen(foo));
						break;
					case 'N':
						// hostname
						if (gethostname(foo, sizeof(foo)) < 0) {
							// no hostname
							strncat(new_footer, "NA", 2);
						} else {
							strncat(new_footer, foo, strlen(foo));
						}
						break;
					case 'u':
						// username
						pwd = getpwuid(getuid());
						if (pwd == NULL) {
							strncat(new_footer, "NA", 2);
						} else {
							snprintf(foo, sizeof(foo), "%s", pwd -> pw_name);
							strncat(new_footer, foo, strlen(foo));
						}
						break;
					case 'R':
						// runtime
						snprintf(foo, 256, "%d", (int)(spider_end - spider_start));
						strncat(new_footer, foo, strlen(foo));
						break;
					case '%':
					default:
						break;

				} // end switch
			} else if (*cp == '\\') {
				switch (*++cp) {
					case 'n': 
						// newline
						strncat(new_footer, "\n", 1);
					case 'r':
						// CR
						strncat(new_footer, "\r", 1);
					case 'f':
						// formfeed
						strncat(new_footer, "\f", 1);
					case 't':
						strncat(new_footer, "\t", 1);
					case 'a':
						strncat(new_footer, "\a", 1);
					case '\\':
						strncat(new_footer, "\\", 1);
					default:
						break;

				} // end switch
			} else {
				strncat(new_footer, cp, 1);
			}
	} // end for

	// OK, new footer is done
	if (Encrypt) {
		// append to the log array
		p = (struct logarray *)malloc(sizeof(struct logarray));
		if (p == NULL) {
			fprintf(stderr, "malloc: %s\n", strerror(errno));
			exit(1);
		}
		p -> next = NULL;
		currlog -> next = p;
		bzero(p -> entry, LOG_MAX);
		// currlog = p;
		snprintf(currlog -> entry, LOG_MAX, "%s", new_footer);
		
	} else {
		if (LogStdout) {
			fprintf(stdout, "%s\n", new_footer);
			(void)fflush(stdout);
		} else {
			fprintf(logfp, "%s\n", new_footer);
			fflush(logfp);
		}
	}

	return;
}

void read_maxgroups(char *pPath) {
	int i;
	AppData *ad;
	int f;

	XML_Parser p = XML_ParserCreateNS(NULL, '|');
	if (!p) {
		fprintf(stderr, "Couldn't allocate memory for parser!\n"); 
		exit(1);
	}

	ad = newAppData();

	// null them out
	for (i = 0; i < 1000; i++) {
		maxgroup[i] = -1; // no way a 2 digit group # will match that
	}

	// parse the SSN.xml we've been passed and populate the maxgroup 
	// array
	
	XML_SetUserData(p, (void *) ad);
	XML_SetElementHandler(p, start, end);
	XML_SetNamespaceDeclHandler(p, ns_start, ns_end);

	f = open(pPath, O_RDONLY);
	if (f < 0) {
		fprintf(stderr, "can't open %s: %s\n", pPath, 
				strerror(errno));
		exit(1);
	}

	for (;;) {
    		char *buff;
    		int len;

    		buff = XML_GetBuffer(p, CHUNK_SIZE);
    		if (! buff) {
     			 fprintf(stderr, "parse buffer\n");
      			exit(1);
    		}

	    	len = read(f, buff, CHUNK_SIZE);
    		if (len < 0) {
			fprintf(stderr, "XML read error\n");
			exit(1);
    		}

    		if (! XML_ParseBuffer(p, len, len == 0)) {
      			fprintf(stderr, "Parse error at line %d:\n%s\n",
       		        XML_GetCurrentLineNumber(p),
       		        XML_ErrorString(XML_GetErrorCode(p)));
      			exit(1);
    		}

   		if (len == 0) {
      			break;
		}
  	}


	return;
}

void start(void *data, const char *el, const char **attr) {
  AppData	*ad = (AppData *) data;
  int		i;
  int area = 999;
  int group = -1;

    for (i = 0; attr[i]; i += 2) {
      if (!strcmp(attr[i], "val")) {
		area = atoi(attr[i + 1]);
	}
      if (!strcmp(attr[i], "group")) {
	      group = atoi(attr[i + 1]);
	}
    } // end for

    maxgroup[area] = group;

  ad->depth++;

}  

void end(void *data, const char *el) {
  AppData *ad = (AppData *) data;

  ad->depth--;
  ad->indent[ad->depth * 2] = '\0';
} 

void ns_start(void *data, const char *prefix, const char *uri) {

}

void ns_end(void *data, const char *prefix) {

}

AppData *newAppData(void) {
  AppData *ret;

  ret = (AppData *) malloc(sizeof(AppData));

  if (ret == NULL) {
    fprintf(stderr, "Couldn't allocate memory for application data\n");
    exit(1);
  }


  ret->depth = 0;
  ret->indent[0] = '\0';
  return(ret);
} 

void generate_key(void) {
	int i;
	// we'll take the first 16 bytes of the password
	char *cp;

	bzero(KEY, sizeof(KEY));
	cp = &Password[0];

	for (i = 0; i < 16; i++) {
		KEY[i] = *cp;
		cp++;
	}

	return;

}

void generate_iv(void) {
	int i;
	unsigned char bf_iv[32];
	unsigned char *cp;

	bzero(IV, sizeof(IV));
	snprintf(bf_iv, 32, "%s", BF_IV);
	cp = &bf_iv[0];

	for (i = 0; i < 8; i++) {
		IV[i] = *cp;	
		cp++;
	}

	return;
}

// Blowfish encrypt and decrypt routines shamelessly stolen from the Web
// I'll keep these as-designed to accept input and output file descriptors 
// as it makes Spider's life a little easier WRT the log viewer, etc.

int spider_encrypt(void) {
	unsigned char outbuf[LOG_MAX + EVP_MAX_BLOCK_LENGTH];
	int olen,tlen,n;
	EVP_CIPHER_CTX ctx;
	struct logarray *p;
	struct logarray *tp;

	EVP_CIPHER_CTX_init (&ctx);
	EVP_EncryptInit(&ctx, EVP_bf_cbc(), KEY, IV);

	// walk through the log array, encrypting as we go.
	// when we finish, call EVP_EncryptFinal and write that to the log

	p = startlog;

	while (p && (strlen(p -> entry))) {
		n = strlen(p -> entry);
		if (EVP_EncryptUpdate(&ctx, outbuf, &olen, p -> entry, n) != 1) {
			return 0;
		}
		fwrite(outbuf, 1, olen, logfp);
		p = p -> next;
	}

	if (EVP_EncryptFinal(&ctx, outbuf+olen, &tlen) != 1) {
		return 0;
	}

	fwrite(outbuf+olen, 1, tlen, logfp);
	EVP_CIPHER_CTX_cleanup(&ctx);

	p = startlog;
	while (p) {
		tp = p -> next;
		p = realloc(p, 0);
		p = tp;
	}

	return 1;
}

int spider_decrypt(void) {
	unsigned char outbuf[LOG_MAX];
	int olen,tlen,n;
	char inbuff[LOG_MAX + EVP_MAX_BLOCK_LENGTH];
	char baz[LOG_MAX + EVP_MAX_BLOCK_LENGTH];
	EVP_CIPHER_CTX ctx;
	int i;

	// hmmm.  how are we going to chop this back into lines and populate
	// the log array?

	if (logfp) {
		fclose(logfp);
	}

	logfp = fopen(LogPath, "rb");

	if (logfp == NULL) {
		fprintf(stderr, "logfp: %s\n", strerror(errno));
		exit(1);
	}

	EVP_CIPHER_CTX_init(&ctx);

	EVP_DecryptInit(&ctx, EVP_bf_cbc(), KEY, IV);

	while ((n = fread(inbuff, 1, LOG_MAX + EVP_MAX_BLOCK_LENGTH, logfp)) > 0) {
		if (EVP_DecryptUpdate(&ctx, outbuf, &olen, inbuff, n) != 1) {
			return 0;
		}
		snprintf(baz, olen+1, "%s", outbuf);
		bzero(&inbuff, LOG_MAX + EVP_MAX_BLOCK_LENGTH);
	}

	if ((i = EVP_DecryptFinal(&ctx, outbuf+olen, &tlen)) != 1) {
		return 0;
	}
	bzero(baz, sizeof(baz));
	snprintf(baz, tlen+1, "%s", outbuf+olen);
	printf("%s", baz);
	EVP_CIPHER_CTX_cleanup(&ctx);
	return 1;
}

void view_log(char *logpath) {
	// we'll try to deal with the log ;
	// if we've got libmagic support, we'll see what kind of file it is
	// "data" is probably encrypted and we'll treat it as such
	// ASCII-something is plaintext and we'll just display it
	int encrypted = 0;
#ifdef HAVE_LIBMAGIC
	const char *type;

	type = magic_file(magic, logpath);

	if (strstr(type, "data")) {
		// log is encrypted
		encrypted = 1;
	} else if (strstr(type, "ASCII")) {
		// log is plaintext
		encrypted = 0;
	} else {
		// huh?  complain.
	}
#else
	encrypted = Encrypt;
#endif

	return;
}

void sanity_check(void) {

	if (AppendLog && Encrypt) {
		fprintf(stderr, "AppendLog and Encrypt are mutually exclusive\n");
		exit(1);
	}

	if (WhenDone & EXIT_WHEN_DONE) {
		if ((WhenDone & RESTORE_WHEN_DONE) || (WhenDone & VIEWLOG_WHEN_DONE)) {
			fprintf(stderr, "Exit-when-done takes precedence over other operations.\n");
			exit(1);
		}
	}

	return;
}

void stop_spider(void) {

	if (!worker) { return; }

	if (kill(worker, SIGTERM)) {
		fprintf(stderr, "SIGTERM to spider worker process failed: %s\n",
				strerror(errno));
		exit(1);
	}

	waitpid(worker, NULL, WNOHANG);

	worker = 0;

	return;

}

void set_globs(void) {
	struct skippaths *p;
	char tempglob[PATH_MAX];
	int status = 0;
	int REG_FLAGS = 0;

	p = startskippath;

	// wouldn't hurt to pre-compile patterns at this point for 
	// easier reuse

	if (CaseSensPath) {
		// paths are case insensitive
		REG_FLAGS = REG_EXTENDED|REG_NOSUB|REG_ICASE;
	} else {
		REG_FLAGS = REG_EXTENDED|REG_NOSUB;
	}

	while (p) {
		bzero(p -> skip2glob, PATH_MAX);
		p -> wildcards = 0;
		if (strstr(p -> skippath, "*") || strstr(p -> skippath, "?")) {
			glob2regex(p -> skippath, &tempglob[0]);
			snprintf(p -> skip2glob, PATH_MAX, "%s", tempglob);
			p -> wildcards = 1;
			status = regcomp(&p -> skip2regex, p -> skip2glob,
					REG_FLAGS);
			if (status != 0) {
				fprintf(stderr, "regex compile error: %s\n",
						strerror(errno));
				exit(1);
			}
		}
		p = p -> next;
	}

	return;

}

void glob2regex(char *inpath, char *outpath) {
	char *cp;

	cp = inpath;

	bzero(outpath, PATH_MAX);
	
	for ( ; *cp; ++cp) {
		switch (*cp) {
			case '\0':
				--cp;
				break;
			case '(':
			case ')':
			case '.':
			case '+':
			case '^':
			case '{':
			case '}':
			case '$':
				strncat(outpath, "\\\\", 2);
				strncat(outpath, cp, 1);
				break;
			case '?':
				strncat(outpath, ".", 1);
				break;
			case '*':
				strncat(outpath, ".*", 2);
				break;
			case '\\':
				strncat(outpath, "\\\\", 2);
				break;
			case ':':
				strncat(outpath, "\\:", 2);
				break;
			default:
				strncat(outpath, cp, 1);
				break;	
		}
	}

	return;
}
