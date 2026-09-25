// WipeCodeSB.m — SpringBoard half of WipeCode.
//
// Settings.app cannot call FBSSystemService directly: it requires the
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
#import <objc/message.h>
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

// Every loaded class name, sorted. objc_getClassList is the public route here;
// objc_copyClassNames is not declared in the iOS SDK.
static NSArray<NSString *> *Vo1dekAllClassNames(void) {
    unsigned int count = objc_getClassList(NULL, 0);
    // The runtime can grow between the two calls, so ask for headroom and clamp
    // to whatever actually came back.
    unsigned int capacity = count + 64;
    Class *buffer = (Class *)malloc(sizeof(Class) * capacity);
    if (buffer == NULL) return @[];

    count = objc_getClassList(buffer, capacity);
    NSMutableArray<NSString *> *names = [NSMutableArray arrayWithCapacity:count];
    for (unsigned int i = 0; i < count; i++) {
        const char *name = class_getName(buffer[i]);
        if (name != NULL) [names addObject:@(name)];
    }
    free(buffer);

    [names sortUsingSelector:@selector(compare:)];
    return names;
}

static NSArray<NSString *> *Vo1dekClassesMatching(const char *needle) {
    NSMutableArray<NSString *> *hits = [NSMutableArray array];
    for (NSString *name in Vo1dekAllClassNames()) {
        if ([name rangeOfString:@(needle)].location != NSNotFound) [hits addObject:name];
    }
    return hits;
}

// Names only: a cheap way to find out what a family is actually called on this
// iOS build before committing to it.
static void Vo1dekDumpClassesMatching(const char *needle) {
    NSArray<NSString *> *hits = Vo1dekClassesMatching(needle);
    Vo1dekLog(@"[probe] --- classes matching '%s': %lu ---", needle, (unsigned long)hits.count);
    for (NSString *name in hits) {
        Vo1dekLog(@"[probe]   %@", name);
    }
}

// The exact argument keys accepted by the erase call cannot be read out of a
// method list, so on first run we dump the real API surface of the classes and
// helpers we rely on. Type encodings fully determine each signature, which is
// enough to write the call correctly without guessing.
static void Vo1dekDumpMethodsOf(const char *className) {
    Class cls = objc_getClass(className);
    if (cls == Nil) {
        Vo1dekLog(@"[probe] class %s: NOT FOUND", className);
        return;
    }
    Vo1dekLog(@"[probe] === %s @ %p ===", className, (__bridge void *)cls);

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

// Bump this whenever the probe below changes. The completion marker carries the
// version, so an upgraded build re-probes on its own instead of needing the user
// to hand-delete probe.log first.
#define VO1DEK_PROBE_VERSION 3

static void Vo1dekRunProbeIfNeeded(void) {
    // The log file already exists by the time we get here — the boot line above
    // created it — so the completion marker is what decides, not the file.
    NSString *existing = [NSString stringWithContentsOfFile:VO1DEK_PROBE
                                                  encoding:NSUTF8StringEncoding
                                                     error:NULL];
    NSString *marker = [NSString stringWithFormat:@"[probe] done v%d", VO1DEK_PROBE_VERSION];
    if ([existing rangeOfString:marker].location != NSNotFound) return;

    Vo1dekLog(@"[probe] ==== run v%d ====", VO1DEK_PROBE_VERSION);

    // v2 answered the open question: there is no SBDeviceErase, and the real
    // argument class for -dataResetWithRequest:completion: is FBSDataResetRequest.
    // What is still unknown is how that request is meant to be built, so this
    // round is narrow and only inspects the two classes involved.
    Vo1dekDumpMethodsOf("FBSDataResetRequest");
    Vo1dekDumpMethodsOf("FBSSystemService");

    // The pane never showed up, so record the pane-hosting classes that do exist
    // rather than assuming PSWebView is the one in use.
    Vo1dekDumpClassesMatching("PSWeb");
    Vo1dekDumpClassesMatching("PSBundle");
    Vo1dekDumpClassesMatching("PreferenceBundles");
    Vo1dekDumpClassesMatching("PSViewController");

    Vo1dekLog(@"[probe] done v%d", VO1DEK_PROBE_VERSION);
}


#pragma mark - erasing

static void Vo1dekPublishResult(BOOL ok, NSString *method, NSString *error) {
    Vo1dekWritePlist(@{@"ok": @(ok), @"method": method ?: @"", @"error": error ?: @""}, VO1DEK_RESULT);
    CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                                         (__bridge CFStringRef)VO1DEK_NOTIFY_RESULT,
                                         NULL, NULL, YES);
}

// Primary path, and the only one the device probe supports.
//
// The probe on iOS 16 found no SBDeviceErase at all, but it did find both halves
// of a real call: FBSSystemService -dataResetWithRequest:completion:, and
// FBSDataResetRequest as the argument class. The request is allocated directly
// rather than fetched from a factory, so the argument keys still have to be
// confirmed against the class's own properties on the device.
static BOOL Vo1dekEraseViaSystemService(NSString **outError) {
    Class serviceCls = NSClassFromString(@"FBSSystemService");
    if (serviceCls == Nil) {
        *outError = @"FBSSystemService not present";
        return NO;
    }
    Class requestCls = NSClassFromString(@"FBSDataResetRequest");
    if (requestCls == Nil) {
        *outError = @"FBSDataResetRequest not present";
        return NO;
    }

    SEL serviceSel = NSSelectorFromString(@"sharedService");
    if (![serviceCls respondsToSelector:serviceSel]) {
        *outError = @"+sharedService not present";
        return NO;
    }
    id service = ((id (*)(id, SEL))objc_msgSend)((id)serviceCls, serviceSel);
    if (service == nil) {
        *outError = @"+sharedService returned nil";
        return NO;
    }

    SEL performSel = NSSelectorFromString(@"dataResetWithRequest:completion:");
    if (![service respondsToSelector:performSel]) {
        *outError = @"dataResetWithRequest:completion: not present";
        return NO;
    }

    id request = [requestCls new];
    if (request == nil) {
        *outError = @"FBSDataResetRequest alloc/init returned nil";
        return NO;
    }

    // The probe could read method signatures but not the meaning of the argument
    // keys, so record the properties the class actually declares. Whichever of
    // them the service needs is then set from the same names in the next round.
    NSArray<NSString *> *keys = @[@"eraseOption", @"EraseOption", @"passcode",
                                  @"Passcode", @"wipeCode", @"shouldErase",
                                  @"options", @"flags", @"eraseAllContentAndSettings"];
    for (NSString *key in keys) {
        SEL sel = NSSelectorFromString(key);
        if (![request respondsToSelector:sel]) continue;
        @try {
            id current = [request valueForKey:key];
            Vo1dekLog(@"[erase] request property %@ = %@", key, current);
        } @catch (NSException *e) {
            Vo1dekLog(@"[erase] request property %@ unreadable: %@", key, e.reason);
        }
    }

    Vo1dekLog(@"[erase] dispatching dataResetWithRequest: request=%@", request);
    void (*perform)(id, SEL, id, id) = (void (*)(id, SEL, id, id))objc_msgSend;
    perform(service, performSel, request, ^(BOOL success, NSError *error) {
        Vo1dekLog(@"[erase] dataReset completion success=%d error=%@", (int)success, error);
        Vo1dekPublishResult(success, @"dataResetWithRequest", error.localizedDescription ?: @"");
    });
    return YES;
}

// Fallback for builds where the system service path does not answer. It needs
// passwordless sudo, which the user sets up once by creating
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
    NSString *error = nil;
    if (Vo1dekEraseViaSystemService(&error)) return;
    Vo1dekLog(@"[erase] dataReset path unavailable: %@", error);

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

    // Reading private SpringBoard state and spawning helper processes from inside
    // the constructor runs while SpringBoard is still initialising, which is a good
    // way to take it down. Let the boot sequence finish first.
    dispatch_async(dispatch_get_main_queue(), ^{
        Vo1dekPublishDeviceInfo();
        Vo1dekRunProbeIfNeeded();
    });

    // Registered synchronously so a request that arrives during startup is not lost.
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
