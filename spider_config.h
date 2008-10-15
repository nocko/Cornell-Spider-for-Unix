#include <pcre.h>
#include <regex.h>

#ifndef PATH_MAX
#define PATH_MAX	1024
#endif

#ifndef LOG_MAX
#define LOG_MAX		2048
#endif

#define IP_SIZE 1024
#define OP_SIZE 1032

#define LOG_PATH	1
#define LOG_TYPE	2
#define LOG_SIZE	4
#define LOG_CTIME	8
#define LOG_ATIME	16
#define LOG_MTIME	32
#define LOG_REGEX	64
#define LOG_MATCH	128
#define LOG_HOSTNAME	256
#define LOG_TOTM	512
#define LOG_SCORE	1024
#define LOG_OWNUID	2048
#define LOG_HASH	4096
#define LOG_NONZERO_SCORE	8192

#define VALIDATOR_NONE	1
#define VALIDATOR_SSN	2
#define VALIDATOR_LUHN	4

#define EXIT_WHEN_DONE		1
#define RESTORE_WHEN_DONE	2
#define VIEWLOG_WHEN_DONE	4

#define CHUNK_SIZE 8192
#define MAX_INDENT 30

#define CONFIG_NAME	"spider.conf"

#define BF_IV		"-,.V<HM,q7:Ibh`>"

#define OVECCOUNT 	30
// struct pathlist {
// 	char path[PATH_MAX];
// 	struct pathlist *next;
// };

struct logarray {
	char entry[LOG_MAX];
	struct logarray *next;
};

struct logarray *startlog = NULL;
struct logarray *currlog = NULL;

struct skiptypes {
	char type[128];
	struct skiptypes *next;
};

struct skippaths {
	char skippath[PATH_MAX];
	int wildcards;
	char skip2glob[PATH_MAX];
	regex_t skip2regex;
	struct skippaths *next;
};

struct skippaths *startskippath = NULL;
struct skippaths *currskippath = NULL;

struct skiptypes *startskip = NULL;
struct skiptypes *currskip = NULL;

struct pathlist *startpath;
struct pathlist *nextpath;

struct regstruct {
	char regtext[256];
	int validator;
        const char *error;
        int erroffset;
        int ovector[OVECCOUNT];
        int count;
        pcre *Pcre;
	pcre_extra *pe;
        struct regstruct *next;
};

struct regstruct reSSN;
struct regstruct reVMCD;
struct regstruct reAMEX;

typedef struct app_data {
	int depth;
	char indent[MAX_INDENT * 2];
} AppData;


int maxgroup[1000];

// function defines
//
void run_spider(char *pPath);
//struct pathlist *acquire_paths(struct pathlist *startp, char *startpath, int rec);
void acquire_paths(char *startpath, int rec);
void scan(char *pPath);
int is_match(char *to_match, int readSize);
void send_match(char *rehit, char *pPath);
void write_log(char *regex, char *frag, char *pPath);
void load_regexes(void);
void compile_regexes(void);
void load_magic(void);
void read_config(void);
void save_config(char *confpath);
void set_globals(void);
void set_fac(char *logfac);
void craft_csv_entry(char *csventry, char *pPath, char *regex, char *hit);
int pcre_callout_spider(pcre_callout_block *block);
void get_ext(char *pPath, char *ext);
void process_zlib(char *pPath);
void process_bzip2(char *pPath);
void process_zip(char *pPath);
void process_mbx(char *pPath);
void make_custom_log_path(void);
void sanitize_buf(char *buf);
void write_footer(void);
int validate_ssn(char *SSN);
int validate_luhn(char *CCN);
void read_maxgroups(char *pPath);
void start(void *data, const char *el, const char **attr);
void end(void *data, const char *el);
void ns_start(void *data, const char *prefix, const char *uri);
void ns_end(void *data, const char *prefix);
AppData *newAppData(void);
void generate_key(void);
void generate_iv(void);
void sanity_check(void);
void view_log(char *logpath);
int spider_encrypt(void);
int spider_decrypt(void);
void stop_spider(void);
void set_globs(void);
void glob2regex(char *inpath, char *outpath);
int maxarea(int alloc, int group);
