#define APPLINK_STDIN    1
#define APPLINK_STDOUT   2
#define APPLINK_STDERR   3
#define APPLINK_FPRINTF  4
#define APPLINK_FGETS    5
#define APPLINK_FREAD    6
#define APPLINK_FWRITE   7
#define APPLINK_FSETMOD  8
#define APPLINK_FEOF     9
#define APPLINK_FCLOSE   10
#define APPLINK_FOPEN    11
#define APPLINK_FSEEK    12
#define APPLINK_FTELL    13
#define APPLINK_FFLUSH   14
#define APPLINK_FERROR   15
#define APPLINK_CLEARERR 16
#define APPLINK_FILENO   17
#define APPLINK_OPEN     18
#define APPLINK_READ     19
#define APPLINK_WRITE    20
#define APPLINK_LSEEK    21
#define APPLINK_CLOSE    22
#define APPLINK_MAX      22

#include <stdio.h>
#include <io.h>
#include <fcntl.h>

static void *app_stdin(void)  { return stdin; }
static void *app_stdout(void) { return stdout; }
static void *app_stderr(void) { return stderr; }

static int app_feof(FILE *fp)         { return feof(fp); }
static int app_ferror(FILE *fp)       { return ferror(fp); }
static void app_clearerr(FILE *fp)    { clearerr(fp); }
static int app_fileno(FILE *fp)       { return _fileno(fp); }
static int app_fsetmod(FILE *fp, char mod) { return _setmode(_fileno(fp), mod == 'b' ? _O_BINARY : _O_TEXT); }

__declspec(dllexport) void **OPENSSL_Applink(void)
{
    static void *applink_table[APPLINK_MAX + 1] = {
        (void *)APPLINK_MAX,
        app_stdin,
        app_stdout,
        app_stderr,
        fprintf,
        fgets,
        fread,
        fwrite,
        app_fsetmod,
        app_feof,
        fclose,
        fopen,
        fseek,
        ftell,
        fflush,
        app_ferror,
        app_clearerr,
        app_fileno,
        open,
        read,
        write,
        lseek,
        close
    };
    return applink_table;
}
