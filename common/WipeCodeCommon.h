#ifndef VO1DEK_WIPECODE_COMMON_H
#define VO1DEK_WIPECODE_COMMON_H

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonHMAC.h>
#import <stdarg.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>
#import <unistd.h>
#import <errno.h>
#import <spawn.h>
#import <sys/wait.h>

/* Cross-process Darwin notification names.
   These are plain strings: any process may observe or post them, which is
   exactly why every payload is authenticated with the HMAC below. */
#define VO1DEK_NOTIFY_REQUEST @"com.vo1dek.wipecode.request"
#define VO1DEK_NOTIFY_RESULT  @"com.vo1dek.wipecode.result"
#define VO1DEK_NOTIFY_DEVICE  @"com.vo1dek.wipecode.device"

/* Shared state directory. Both SpringBoard and Settings run as UID mobile,
   so this path is writable and readable from either side without privileges. */
#define VO1DEK_DIR      @"/var/mobile/Library/WipeCode"
#define VO1DEK_SECRET   (VO1DEK_DIR @"/secret.plist")   /* {salt, digest}   - written by pref  */
#define VO1DEK_DEVICE   (VO1DEK_DIR @"/device.plist")   /* {type, raw}      - written by sb    */
#define VO1DEK_REQUEST  (VO1DEK_DIR @"/request.plist")  /* {digest}         - written by pref  */
#define VO1DEK_RESULT   (VO1DEK_DIR @"/result.plist")   /* {ok, method, ...}- written by sb    */
#define VO1DEK_PROBE    (VO1DEK_DIR @"/probe.log")     /* append-only diagnostics            */

static inline NSString *Vo1dekRandomHex(unsigned int byteCount) {
    NSMutableData *d = [NSMutableData dataWithLength:byteCount];
    if (d.length && SecRandomCopyBytes(kSecRandomDefault, byteCount, d.mutableBytes) != errSecSuccess) {
        arc4random_buf(d.mutableBytes, byteCount);
    }
    const unsigned char *p = (const unsigned char *)d.bytes;
    NSMutableString *hex = [NSMutableString stringWithCapacity:byteCount * 2];
    for (unsigned int i = 0; i < byteCount; i++) {
        [hex appendFormat:@"%02x", p[i]];
    }
    return hex;
}

static inline NSString *Vo1dekHMAC(NSString *secret, NSString *message) {
    NSData *k = [secret dataUsingEncoding:NSUTF8StringEncoding] ?: [NSData data];
    NSData *m = [message dataUsingEncoding:NSUTF8StringEncoding] ?: [NSData data];
    unsigned char mac[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, k.bytes, (size_t)k.length, m.bytes, (size_t)m.length, mac);
    NSMutableString *hex = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (NSUInteger i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [hex appendFormat:@"%02x", mac[i]];
    }
    return hex;
}

/* Comparison whose duration does not depend on where the first difference is. */
static inline BOOL Vo1dekSecretEquals(NSString *a, NSString *b) {
    if (a.length == 0 || b.length == 0 || a.length != b.length) return NO;
    const char *x = a.UTF8String;
    const char *y = b.UTF8String;
    unsigned char diff = 0;
    for (NSUInteger i = 0; i < a.length; i++) {
        diff |= (unsigned char)(x[i] ^ y[i]);
    }
    return diff == 0;
}

static inline void Vo1dekEnsureDir(void) {
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:VO1DEK_DIR]) {
        [fm createDirectoryAtPath:VO1DEK_DIR
      withIntermediateDirectories:YES
                       attributes:@{NSFilePosixPermissions: @0770}
                            error:NULL];
    }
}

static inline NSDictionary *Vo1dekReadPlist(NSString *path) {
    NSData *d = [NSData dataWithContentsOfFile:path];
    if (d.length == 0) return nil;
    id plist = [NSPropertyListSerialization propertyListWithData:d
                                                         options:NSPropertyListImmutable
                                                          format:NULL
                                                           error:NULL];
    return [plist isKindOfClass:[NSDictionary class]] ? plist : nil;
}

/* Shared append-only diagnostic log. Both halves write here so a single file
   shows the full sequence: request written, notification received, erase
   dispatched, completion reported. */
static inline void Vo1dekLog(NSString *format, ...) {
    va_list args;
    va_start(args, format);
    NSString *line = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);

    static NSDateFormatter *stamp;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        stamp = [NSDateFormatter new];
        stamp.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
        stamp.dateFormat = @"yyyy-MM-dd HH:mm:ss";
    });

    Vo1dekEnsureDir();

    // Truncate once past ~512 KB so an endless respring loop cannot fill the volume.
    NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:VO1DEK_PROBE error:NULL];
    if ([attrs fileSize] > 512 * 1024) {
        [[NSFileManager defaultManager] removeItemAtPath:VO1DEK_PROBE error:NULL];
    }

    NSString *entry = [NSString stringWithFormat:@"[%@] %@\n", [stamp stringFromDate:[NSDate date]], line];
    NSData *data = [entry dataUsingEncoding:NSUTF8StringEncoding];
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:VO1DEK_PROBE];
    if (fh == nil) {
        [[NSFileManager defaultManager] createFileAtPath:VO1DEK_PROBE contents:data attributes:nil];
        return;
    }
    @try {
        [fh seekToEndOfFile];
        [fh writeData:data];
        [fh closeFile];
    } @catch (NSException *e) {
        // Nothing useful to do if the log itself is unwritable.
    }
}

/* Runs a helper and returns its combined stdout/stderr. NSTask is not declared in
   the iOS SDK, so this goes through posix_spawn. A NULL envp means the child
   inherits this process's environment; every path we pass is absolute, so PATH is
   not consulted. */
static inline NSString *Vo1dekRunProcess(NSString *launchPath, NSArray<NSString *> *arguments, int *outStatus) {
    if (outStatus) *outStatus = -1;
    if (![[NSFileManager defaultManager] isExecutableFileAtPath:launchPath]) return nil;

    NSUInteger argc = arguments.count;
    char **argv = calloc(argc + 2, sizeof(char *));
    if (argv == NULL) return nil;

    argv[0] = strdup(launchPath.fileSystemRepresentation);
    for (NSUInteger i = 0; i < argc; i++) {
        argv[i + 1] = strdup([arguments[i] stringByStandardizingPath].fileSystemRepresentation);
    }
    argv[argc + 1] = NULL;

    int fds[2];
    if (pipe(fds) != 0) {
        for (NSUInteger i = 0; i <= argc + 1; i++) free(argv[i]);
        free(argv);
        return nil;
    }

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_addclose(&actions, fds[0]);
    posix_spawn_file_actions_adddup2(&actions, fds[1], STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&actions, fds[1], STDERR_FILENO);
    posix_spawn_file_actions_addclose(&actions, fds[1]);

    pid_t pid = 0;
    int rc = posix_spawn(&pid, launchPath.fileSystemRepresentation, &actions, NULL, argv, NULL);
    posix_spawn_file_actions_destroy(&actions);
    close(fds[1]);

    if (rc != 0) {
        close(fds[0]);
        for (NSUInteger i = 0; i <= argc + 1; i++) free(argv[i]);
        free(argv);
        return [NSString stringWithFormat:@"posix_spawn failed: %s", strerror(rc)];
    }

    NSMutableData *output = [NSMutableData data];
    char buffer[4096];
    ssize_t got;
    while ((got = read(fds[0], buffer, sizeof(buffer))) > 0) {
        [output appendBytes:buffer length:(NSUInteger)got];
    }
    close(fds[0]);

    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) { }
    if (outStatus) *outStatus = status;

    for (NSUInteger i = 0; i <= argc + 1; i++) free(argv[i]);
    free(argv);

    return [[NSString alloc] initWithData:output encoding:NSUTF8StringEncoding] ?: @"";
}

static inline BOOL Vo1dekWritePlist(NSDictionary *plist, NSString *path) {
    Vo1dekEnsureDir();
    NSError *err = nil;
    NSData *d = [NSPropertyListSerialization dataWithPropertyList:plist
                                                            format:NSPropertyListBinaryFormat_v1_0
                                                           options:0
                                                             error:&err];
    if (d.length == 0) return NO;
    return [d writeToFile:path options:NSDataWritingAtomic error:&err];
}

#endif /* VO1DEK_WIPECODE_COMMON_H */
