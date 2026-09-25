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

// The SpringBoard-side probe is retired. v2 found that SBDeviceErase does not
// exist and that FBSDataResetRequest is the real argument class; v3 produced its
// designated initialiser, - initWithMode:options:reason:. Everything still
// unknown belongs to the Settings pane, and those classes only exist inside the
// Preferences process, so probing them from SpringBoard could only ever report
// them as absent. The Settings half owns the probe now.

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

    SEL initSel = NSSelectorFromString(@"initWithMode:options:reason:");
    if (![requestCls instancesRespondToSelector:initSel]) {
        *outError = @"initWithMode:options:reason: not present";
        return NO;
    }
    SEL performSel = NSSelectorFromString(@"dataResetWithRequest:completion:");
    if (![service respondsToSelector:performSel]) {
        *outError = @"dataResetWithRequest:completion: not present";
        return NO;
    }

    // The probe gave the designated initialiser as
    //   - initWithMode:options:reason:  @40@0:8q16q24@32
    // so mode and options are both long long and reason is an NSString. What the
    // individual values mean is not visible in a method list, so zero is used for
    // both, which is the default "no extra flags" case, and the reason carries the
    // provenance. If the service rejects it, the completion block reports why and
    // the enum values can be read off a real Settings reset from a disassembly.
    const long long mode = 0;
    const long long options = 0;
    NSString *reason = @"WipeCode authenticated request";

    // objc_msgSend is declared to return void, so the call has to go through a
    // void * and be read back as the id the initialiser actually returns.
    void *raw = ((void *(*)(id, SEL, long long, long long, id))objc_msgSend)(
        (id)requestCls, initSel, mode, options, reason);
    id request = (__bridge_transfer id)raw;
    if (request == nil) {
        *outError = @"initWithMode:options:reason: returned nil";
        return NO;
    }

    // Read the values back so the log shows what the class actually stored rather
    // than what we passed in.
    SEL optionsSel = NSSelectorFromString(@"options");
    SEL modeSel = NSSelectorFromString(@"mode");
    SEL reasonSel = NSSelectorFromString(@"reason");
    Vo1dekLog(@"[erase] request built: mode=%lld options=%lld reason=%@",
              [request respondsToSelector:modeSel]
                  ? ((long long (*)(id, SEL))objc_msgSend)(request, modeSel) : -1,
              [request respondsToSelector:optionsSel]
                  ? ((long long (*)(id, SEL))objc_msgSend)(request, optionsSel) : -1,
              [request respondsToSelector:reasonSel]
                  ? ((id (*)(id, SEL))objc_msgSend)(request, reasonSel) : @"(unreadable)");

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

    // Reading private SpringBoard state from inside the constructor runs while
    // SpringBoard is still initialising, which is a good way to take it down.
    // Let the boot sequence finish first.
    dispatch_async(dispatch_get_main_queue(), ^{
        Vo1dekPublishDeviceInfo();
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
