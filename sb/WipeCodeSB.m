// WipeCodeSB.m — SpringBoard half of WipeCode.
//
// Settings.app cannot call SBDeviceErase directly: FBSSystemService requires the
// com.apple.springboard entitlement, which only the SpringBoard process carries.
// So this half lives in SpringBoard, listens on a Darwin notification, and performs
// the erase on behalf of the Settings pane.
//
// Trust model: a Darwin notification carries no payload and any process may post
// one, so the notification is only a wake-up call. The actual authorisation is an
// HMAC-SHA256 over the typed password, keyed by a per-install random salt. The
// plaintext password never touches the disk or the wire.

#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import "../common/WipeCodeCommon.h"

#pragma mark - device passcode type

// Returns the first value these accessors yield. The spelling of the manager
// accessor and of the type property has moved around between iOS releases, so we
// probe a list rather than hard-coding one and record what actually answered.
static id Vo1dekFirstAvailable(id target, NSArray<NSString *> *names) {
    if (target == nil) return nil;
    for (NSString *name in names) {
        SEL sel = NSSelectorFromString(name);
        if (![target respondsToSelector:sel]) continue;
        @try {
            id value = [target valueForKey:name];
            if (value != nil && value != [NSNull null]) return value;
        } @catch (NSException *e) {
            // Wrong type or unavailable ivar: try the next candidate.
        }
    }
    return nil;
}

static id Vo1dekSharedInstanceOf(NSString *className, NSArray<NSString *> *accessors) {
    Class cls = NSClassFromString(className);
    if (cls == Nil) return nil;
    for (NSString *accessor in accessors) {
        SEL sel = NSSelectorFromString(accessor);
        if (![cls respondsToSelector:sel]) continue;
        @try {
            id instance = ((id (*)(id, SEL))objc_msgSend)((id)cls, sel);
            if (instance) return instance;
        } @catch (NSException *e) {
        }
    }
    return nil;
}

// Maps the raw passcode-type value onto what the Settings pane needs: a keyboard
// type plus a length constraint. The raw value is always reported alongside so a
// wrong mapping here is visible in the log rather than silently mistyping the pad.
static NSDictionary *Vo1dekDescribePasscodeType(NSNumber *raw) {
    if (raw == nil) {
        return @{@"type": @"unknown", @"numeric": @NO, @"min": @4, @"max": @0, @"raw": @(-1)};
    }
    NSInteger v = raw.integerValue;
    // Matches the shape of LSPasscodeType: none, alpha-numeric (4/6/general),
    // numeric (4/6/general), and the legacy numeric-only value.
    NSString *name = nil;
    BOOL numeric = NO;
    NSInteger minLen = 4, maxLen = 0;

    switch (v) {
        case 0: name = @"none"; break;
        case 1: name = @"alphanumeric"; break;
        case 2: name = @"alphanumeric4"; minLen = maxLen = 4; break;
        case 3: name = @"alphanumeric6"; minLen = maxLen = 6; break;
        case 4: name = @"numeric"; numeric = YES; break;
        case 5: name = @"numeric4"; numeric = YES; minLen = maxLen = 4; break;
        case 6: name = @"numeric6"; numeric = YES; minLen = maxLen = 6; break;
        case 7: name = @"numericLegacy"; numeric = YES; break;
        default: name = [NSString stringWithFormat:@"raw%ld", (long)v]; break;
    }

    return @{@"type": name, @"numeric": @(numeric), @"min": @(minLen), @"max": @(maxLen), @"raw": @(v)};
}

static NSDictionary *Vo1dekCurrentPasscodeType(void) {
    NSArray *managers = @[@"SBAuthenticationManager", @"SBLockScreenManager", @"SBDisplayDevice"];
    NSArray *accessors = @[@"sharedAuthenticationManager", @"sharedInstance", @"defaultManager", @"sharedManager", @"defaultInstance"];
    NSArray *typeKeys = @[@"passcodeType", @"_passcodeType", @"passcodeTypeValue", @"type"];

    for (NSString *name in managers) {
        id manager = Vo1dekSharedInstanceOf(name, accessors);
        if (manager == nil) continue;
        id value = Vo1dekFirstAvailable(manager, typeKeys);
        if (![value isKindOfClass:[NSNumber class]]) continue;
        Vo1dekLog(@"[passcode] %@ -> %@", name, value);
        return Vo1dekDescribePasscodeType((NSNumber *)value);
    }

    Vo1dekLog(@"[passcode] no manager answered; reporting unknown");
    return Vo1dekDescribePasscodeType(nil);
}

static void Vo1dekPublishDeviceInfo(void) {
    NSMutableDictionary *plist = [(Vo1dekReadPlist(VO1DEK_DEVICE) ?: @{}) mutableCopy];
    [plist addEntriesFromDictionary:Vo1dekCurrentPasscodeType()];
    Vo1dekWritePlist(plist, VO1DEK_DEVICE);
}

#pragma mark - probe

// The exact argument keys accepted by SBDeviceErase cannot be read out of the
// method list, so on first run we dump the real API surface of the classes and
// helpers we rely on. Type encodings fully determine each signature, which is
// enough to write the call correctly without guessing.
static void Vo1dekDumpMethodsOf(const char *className) {
    Class cls = objc_getClass(className);
    if (cls == Nil) {
        Vo1dekLog(@"[probe] class %s: NOT FOUND", className);
        return;
    }
    Vo1dekLog(@"[probe] === %s @ %p ===", className, (void *)cls);

    unsigned int count = 0;
    Method *meta = class_copyMethodList(object_getClass(cls), &count);
    for (unsigned int i = 0; i < count; i++) {
        Vo1dekLog(@"[probe]   + %s  %s", sel_getName(method_getName(meta[i])),
                  method_getTypeEncoding(meta[i]));
    }
    free(meta);

    count = 0;
    Method *inst = class_copyMethodList(cls, &count);
    for (unsigned int i = 0; i < count; i++) {
        Vo1dekLog(@"[probe]   - %s  %s", sel_getName(method_getName(inst[i])),
                  method_getTypeEncoding(inst[i]));
    }
    free(inst);
}

static void Vo1dekRunCommand(NSString *launchPath, NSArray<NSString *> *arguments) {
    Vo1dekLog(@"[probe] $ %@ %@", launchPath, [arguments componentsJoinedByString:@" "]);
    int status = -1;
    NSString *text = Vo1dekRunProcess(launchPath, arguments, &status);
    if (text == nil) {
        Vo1dekLog(@"[probe]   (not executable or missing)");
        return;
    }
    for (NSString *line in [text componentsSeparatedByString:@"\n"]) {
        if (line.length) Vo1dekLog(@"[probe]   %@", line);
    }
    Vo1dekLog(@"[probe]   exit status %d", status);
}

static void Vo1dekRunProbeIfNeeded(void) {
    // The log file already exists by the time we get here — the boot line above
    // created it — so the completion marker is what decides, not the file.
    NSString *existing = [NSString stringWithContentsOfFile:VO1DEK_PROBE
                                                  encoding:NSUTF8StringEncoding
                                                     error:NULL];
    if ([existing rangeOfString:@"[probe] done"].location != NSNotFound) return;

    Vo1dekLog(@"[probe] first run, dumping API surface");
    Vo1dekDumpMethodsOf("SBDeviceErase");
    Vo1dekDumpMethodsOf("FBSSystemService");
    Vo1dekDumpMethodsOf("FBSSystemServiceRequest");
    Vo1dekDumpMethodsOf("SBAuthenticationManager");
    Vo1dekRunCommand(@"/usr/bin/fdesetup", @[@"-h"]);
    Vo1dekRunCommand(@"/usr/bin/fdesetup", @[@"help"]);
    if ([[NSFileManager defaultManager] fileExistsAtPath:@"/var/jb/usr/bin/sudo"]) {
        Vo1dekRunCommand(@"/var/jb/usr/bin/sudo", @[@"-n", @"true"]);
    }
    Vo1dekLog(@"[probe] done");
}

#pragma mark - erasing

static void Vo1dekPublishResult(BOOL ok, NSString *method, NSString *error) {
    Vo1dekWritePlist(@{@"ok": @(ok), @"method": method ?: @"", @"error": error ?: @""}, VO1DEK_RESULT);
    CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                                         (__bridge CFStringRef)VO1DEK_NOTIFY_RESULT,
                                         NULL, NULL, YES);
}

// Primary path. The completion block is where success is actually reported, so the
// return value only tells us whether the call was dispatched at all.
static BOOL Vo1dekEraseViaSystemService(NSString *label, id arguments, NSString **outError) {
    Class cls = NSClassFromString(@"SBDeviceErase");
    if (cls == Nil) {
        *outError = @"SBDeviceErase not present";
        return NO;
    }

    SEL serviceSel = NSSelectorFromString(@"defaultService");
    if (![cls respondsToSelector:serviceSel]) {
        *outError = @"+defaultService not present";
        return NO;
    }
    id service = ((id (*)(id, SEL))objc_msgSend)((id)cls, serviceSel);
    if (service == nil) {
        *outError = @"+defaultService returned nil";
        return NO;
    }

    SEL performSel = NSSelectorFromString(@"performRequestWithArguments:error:completion:");
    if (![service respondsToSelector:performSel]) {
        *outError = @"performRequestWithArguments:error:completion: not present";
        return NO;
    }

    NSError *err = nil;
    Vo1dekLog(@"[erase] dispatching %@ args=%@", label, arguments);
    void (*perform)(id, SEL, id, NSError **, id) =
        (void (*)(id, SEL, id, NSError **, id))objc_msgSend;
    perform(service, performSel, arguments, &err, ^(BOOL success, NSError *error) {
        Vo1dekLog(@"[erase] %@ completion success=%d error=%@", label, (int)success, error);
        Vo1dekPublishResult(success, label, error.localizedDescription ?: @"");
    });
    if (err != nil) {
        Vo1dekLog(@"[erase] %@ failed before completion: %@", label, err);
    }
    return YES;
}

// Fallback for builds where SBDeviceErase is not reachable from SpringBoard.
// Needs passwordless sudo, which the user sets up once by creating
// /var/jb/etc/sudoers.d/vo1dek containing:
//   mobile ALL=(root) NOPASSWD: /usr/bin/fdesetup
// The argument vector itself is read from secret.plist under "rootEraseArgs" so
// it can be corrected against the real `fdesetup -h` output in the probe log.
static BOOL Vo1dekEraseViaRoot(NSString **outError) {
    NSString *sudoers = @"/var/jb/etc/sudoers.d/vo1dek";
    if (![[NSFileManager defaultManager] fileExistsAtPath:sudoers]) {
        *outError = @"no /var/jb/etc/sudoers.d/vo1dek, root path disabled";
        return NO;
    }

    NSDictionary *secret = Vo1dekReadPlist(VO1DEK_SECRET);
    NSArray *args = secret[@"rootEraseArgs"];
    if (![args isKindOfClass:[NSArray class]] || args.count == 0) {
        *outError = @"rootEraseArgs missing from secret.plist";
        return NO;
    }

    NSString *label = [NSString stringWithFormat:@"fdesetup %@", [args componentsJoinedByString:@" "]];
    int status = -1;
    NSString *text = Vo1dekRunProcess(@"/var/jb/usr/bin/sudo",
                                      [@[@"-n", @"/usr/bin/fdesetup"] arrayByAddingObjectsFromArray:args],
                                      &status);
    if (text == nil) {
        *outError = @"could not run sudo";
        return NO;
    }
    Vo1dekLog(@"[erase] %@ status=%d out=%@", label, status, text);
    BOOL ok = (status == 0);
    Vo1dekPublishResult(ok, label, text);
    if (!ok && *outError == nil) *outError = text;
    return ok;
}

static void Vo1dekPerformErase(void) {
    // Empty arguments first: the service generally applies its default action and
    // the specific keys are the part we could not verify offline.
    NSArray<NSString *> *labels = @[@"empty", @"EraseOption", @"ErasePasscode"];
    NSArray *argumentSets = @[@{}, @{@"EraseOption": @0}, @{@"ErasePasscode": @NO}];

    NSString *error = nil;
    for (NSUInteger i = 0; i < labels.count; i++) {
        if (Vo1dekEraseViaSystemService(labels[i], argumentSets[i], &error)) return;
        Vo1dekLog(@"[erase] %@ unavailable: %@", labels[i], error);
    }

    Vo1dekLog(@"[erase] system service path exhausted, falling back to root");
    if (Vo1dekEraseViaRoot(&error)) return;

    Vo1dekLog(@"[erase] all paths failed: %@", error);
    Vo1dekPublishResult(NO, @"none", error ?: @"no working erase path");
}

#pragma mark - request handling

static void Vo1dekHandleRequest(void) {
    NSDictionary *request = Vo1dekReadPlist(VO1DEK_REQUEST);
    if (request == nil) {
        Vo1dekLog(@"[request] no request file, ignoring");
        return;
    }

    // Consume it first: a request must never be replayable.
    [[NSFileManager defaultManager] removeItemAtPath:VO1DEK_REQUEST error:NULL];

    NSString *candidate = request[@"digest"];
    NSDictionary *secret = Vo1dekReadPlist(VO1DEK_SECRET);
    NSString *salt = secret[@"salt"];
    NSString *expected = secret[@"digest"];

    if (![candidate isKindOfClass:[NSString class]] || candidate.length == 0) {
        Vo1dekLog(@"[request] malformed digest, refusing");
        Vo1dekPublishResult(NO, @"auth", @"malformed request");
        return;
    }
    if (![salt isKindOfClass:[NSString class]] || ![expected isKindOfClass:[NSString class]]) {
        Vo1dekLog(@"[request] no wipe password configured, refusing");
        Vo1dekPublishResult(NO, @"auth", @"no wipe password configured");
        return;
    }
    if (!Vo1dekSecretEquals(candidate, expected)) {
        Vo1dekLog(@"[request] digest mismatch, refusing");
        Vo1dekPublishResult(NO, @"auth", @"wrong password");
        return;
    }

    Vo1dekLog(@"[request] authorised, erasing");
    Vo1dekPerformErase();
}

#pragma mark - notification plumbing

static const void *Vo1dekToken;

static void Vo1dekDarwinCallback(CFNotificationCenterRef center, void *observer,
                                 CFStringRef name, const void *object, CFDictionaryRef userInfo) {
    // Delivered on an arbitrary thread.
    dispatch_async(dispatch_get_main_queue(), ^{
        Vo1dekHandleRequest();
    });
}

static void Vo1dekStart(void) {
    Vo1dekEnsureDir();
    Vo1dekLog(@"[boot] SpringBoard half loaded");

    Vo1dekPublishDeviceInfo();
    Vo1dekRunProbeIfNeeded();

    CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(),
                                    Vo1dekToken,
                                    Vo1dekDarwinCallback,
                                    (__bridge CFStringRef)VO1DEK_NOTIFY_REQUEST,
                                    NULL,
                                    CFNotificationSuspensionBehaviorCoalesce);

    // A request written just before we started observing would otherwise be missed.
    if (Vo1dekReadPlist(VO1DEK_REQUEST) != nil) {
        Vo1dekHandleRequest();
    }
}

%ctor {
    @autoreleasepool {
        Vo1dekStart();
    }
}
