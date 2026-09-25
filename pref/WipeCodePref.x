// WipeCodePref.m — Settings half of WipeCode.
//
// Adds a pane to Settings. The pane is a PSWebView so the layout can be written in
// HTML, but the password is never typed into the web view: the page only posts an
// action name, and every text field is a native UITextField.
//
// The wipe password is stored as HMAC-SHA256(salt, password) with a per-install
// random salt. Only that digest is handed to SpringBoard, so the plaintext never
// reaches the disk.

#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <objc/runtime.h>
#import "../common/WipeCodeCommon.h"

static const char *Vo1dekPaneMarker = "WipeCode.bundle";
static __weak WKWebView *Vo1dekPaneWebView;
static BOOL Vo1dekCountdownCancelled = NO;

#pragma mark - helpers

static UIViewController *Vo1dekTopViewController(void) {
    UIWindow *key = nil;
    for (UIWindow *window in [UIApplication sharedApplication].windows) {
        if (window.isKeyWindow) {
            key = window;
            break;
        }
    }
    if (key == nil) {
        for (UIWindow *window in [UIApplication sharedApplication].windows) {
            if (!window.isHidden) {
                key = window;
                break;
            }
        }
    }
    UIViewController *vc = key.rootViewController;
    while (vc.presentedViewController != nil) {
        vc = vc.presentedViewController;
    }
    return vc;
}

static void Vo1dekPushToPane(NSString *js) {
    WKWebView *pane = Vo1dekPaneWebView;
    if (pane == nil) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        [pane evaluateJavaScript:js completionHandler:nil];
    });
}

static NSDictionary *Vo1dekDeviceInfo(void) {
    return Vo1dekReadPlist(VO1DEK_DEVICE) ?: @{};
}

static NSDictionary *Vo1dekSecret(void) {
    return Vo1dekReadPlist(VO1DEK_SECRET) ?: @{};
}

// Escapes a string for embedding in a JS string literal.
static NSString *Vo1dekJsString(NSString *value) {
    NSData *data = [NSJSONSerialization dataWithJSONObject:@[value ?: @""] options:0 error:NULL];
    NSString *json = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] ?: @"\"\"";
    return [json substringWithRange:NSMakeRange(1, json.length - 2)];
}

static void Vo1dekSendStatus(void) {
    NSDictionary *device = Vo1dekDeviceInfo();
    NSDictionary *secret = Vo1dekSecret();
    NSDictionary *result = Vo1dekReadPlist(VO1DEK_RESULT) ?: @{};

    NSInteger minLen = 4;
    if ([device[@"min"] isKindOfClass:[NSNumber class]]) minLen = [device[@"min"] integerValue];
    NSInteger maxLen = 0;
    if ([device[@"max"] isKindOfClass:[NSNumber class]]) maxLen = [device[@"max"] integerValue];

    NSString *js = [NSString stringWithFormat:
        @"window.vo1dekStatus && window.vo1dekStatus({configured:%@, passcodeType:%@, numeric:%@, min:%d, max:%d, ok:%@, method:%@, error:%@});",
        [secret[@"digest"] isKindOfClass:[NSString class]] ? @"true" : @"false",
        Vo1dekJsString(device[@"type"] ?: @"unknown"),
        [device[@"numeric"] boolValue] ? @"true" : @"false",
        (int)minLen, (int)maxLen,
        [result[@"ok"] boolValue] ? @"true" : @"false",
        Vo1dekJsString(result[@"method"] ?: @""),
        Vo1dekJsString(result[@"error"] ?: @"")];

    Vo1dekLog(@"[pref] status configured=%@ type=%@", secret[@"digest"] != nil, device[@"type"]);
    Vo1dekPushToPane(js);
}

// Adds one secure field whose keyboard follows the passcode type the SpringBoard
// half published for this device.
static void Vo1dekAddPasswordField(UIAlertController *alert, NSString *placeholder) {
    BOOL numeric = [Vo1dekDeviceInfo()[@"numeric"] boolValue];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *tf) {
        tf.placeholder = placeholder;
        tf.secureTextEntry = YES;
        tf.autocorrectionType = UITextAutocorrectionTypeNo;
        tf.autocapitalizationType = UITextAutocapitalizationTypeNone;
        tf.spellCheckingType = UITextSpellCheckingTypeNo;
        tf.textContentType = nil;
        tf.keyboardType = numeric ? UIKeyboardTypeNumberPad : UIKeyboardTypeASCIICapable;
    }];
}

static void Vo1dekShowNotice(NSString *title, NSString *message) {
    UIAlertController *notice = [UIAlertController alertControllerWithTitle:title
                                                                    message:message
                                                             preferredStyle:UIAlertControllerStyleAlert];
    [notice addAction:[UIAlertAction actionWithTitle:@"ОК" style:UIAlertActionStyleDefault handler:nil]];
    UIViewController *presenter = Vo1dekTopViewController();
    if (presenter == nil) return;
    [presenter presentViewController:notice animated:YES completion:nil];
}

#pragma mark - password storage

static void Vo1dekStorePassword(NSString *password) {
    NSString *salt = Vo1dekRandomHex(32);
    NSString *digest = Vo1dekHMAC(salt, password);
    Vo1dekWritePlist(@{@"salt": salt, @"digest": digest}, VO1DEK_SECRET);
    Vo1dekLog(@"[pref] wipe password stored");
    Vo1dekSendStatus();
}

static void Vo1dekClearPassword(void) {
    [[NSFileManager defaultManager] removeItemAtPath:VO1DEK_SECRET error:NULL];
    Vo1dekLog(@"[pref] wipe password cleared");
    Vo1dekSendStatus();
}

#pragma mark - erase request

// Nothing is dispatched until the count reaches zero, and each step dismisses the
// previous alert first — UIKit refuses to present on top of a presented controller.
//
// The cancel flag is honoured here, at the top of each step, because that is where
// the recursive call re-enters. Starting a fresh countdown clears it first, so a
// flag left set by a step whose dismissal callback never fired cannot abort the
// next attempt.
static void Vo1dekCountdownStep(NSString *password, NSInteger remaining) {
    if (Vo1dekCountdownCancelled) {
        Vo1dekCountdownCancelled = NO;
        Vo1dekLog(@"[pref] countdown cancelled");
        Vo1dekSendStatus();
        return;
    }

    if (remaining <= 0) {
        NSString *salt = Vo1dekSecret()[@"salt"];
        if (![salt isKindOfClass:[NSString class]]) {
            Vo1dekLog(@"[pref] cannot arm: no salt");
            Vo1dekShowNotice(@"Ошибка", @"Пароль стирания не настроен.");
            return;
        }
        Vo1dekWritePlist(@{@"digest": Vo1dekHMAC(salt, password)}, VO1DEK_REQUEST);
        Vo1dekLog(@"[pref] request written, notifying SpringBoard");
        CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                                             (__bridge CFStringRef)VO1DEK_NOTIFY_REQUEST,
                                             NULL, NULL, YES);
        return;
    }

    UIAlertController *alert = [UIAlertController
        alertControllerWithTitle:[NSString stringWithFormat:@"Стерть через %ld", (long)remaining]
                         message:@"Будут удалены все данные и настройки."
                  preferredStyle:UIAlertControllerStyleAlert];

    [alert addAction:[UIAlertAction actionWithTitle:@"Отмена" style:UIAlertActionStyleCancel handler:^(UIAlertAction *action) {
        Vo1dekCountdownCancelled = YES;
    }]];

    UIViewController *presenter = Vo1dekTopViewController();
    if (presenter == nil) return;
    [presenter presentViewController:alert animated:NO completion:^{
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            [alert dismissViewControllerAnimated:NO completion:^{
                Vo1dekCountdownStep(password, remaining - 1);
            }];
        });
    }];
}

static void Vo1dekPromptAndMaybeWipe(void) {
    NSDictionary *device = Vo1dekDeviceInfo();
    if (![Vo1dekSecret()[@"digest"] isKindOfClass:[NSString class]]) {
        Vo1dekLog(@"[pref] wipe requested with no password configured");
        Vo1dekShowNotice(@"Не настроено", @"Сначала задайте пароль стирания.");
        return;
    }

    NSString *type = device[@"type"] ?: @"unknown";
    NSInteger minLen = 4, maxLen = 0;
    if ([device[@"min"] isKindOfClass:[NSNumber class]]) minLen = [device[@"min"] integerValue];
    if ([device[@"max"] isKindOfClass:[NSNumber class]]) maxLen = [device[@"max"] integerValue];

    NSString *hint = maxLen > 0
        ? [NSString stringWithFormat:@"Формат устройства: ровно %ld символов.", (long)maxLen]
        : [NSString stringWithFormat:@"Формат устройства: %@, от %ld символов.", type, (long)minLen];

    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Стереть устройство"
                                                                    message:hint
                                                             preferredStyle:UIAlertControllerStyleAlert];
    Vo1dekAddPasswordField(alert, @"Пароль стирания");
    [alert addAction:[UIAlertAction actionWithTitle:@"Отмена" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"Продолжить" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *action) {
        NSString *password = alert.textFields.firstObject.text ?: @"";
        // A tapped action dismisses the alert, and UIKit will not present another
        // controller on top of one that is still on screen. Hand the follow-up to
        // the next main-queue turn so the dismissal has committed first.
        dispatch_async(dispatch_get_main_queue(), ^{
            if (password.length < (NSUInteger)minLen || (maxLen > 0 && password.length != (NSUInteger)maxLen)) {
                Vo1dekLog(@"[pref] length check failed: got %lu, want %ld..%ld",
                          (unsigned long)password.length, (long)minLen, (long)maxLen);
                Vo1dekShowNotice(@"Неверная длина", @"Пароль не соответствует формату код-пароль этого устройства.");
                return;
            }
            Vo1dekCountdownCancelled = NO;
            Vo1dekCountdownStep(password, 5);
        });
    }]];

    UIViewController *presenter = Vo1dekTopViewController();
    if (presenter == nil) return;
    [presenter presentViewController:alert animated:YES completion:nil];
}

#pragma mark - password setup

static void Vo1dekPromptForNewPassword(BOOL confirming, NSString *firstEntry) {
    NSDictionary *device = Vo1dekDeviceInfo();
    NSString *type = device[@"type"] ?: @"unknown";
    NSInteger minLen = 4;
    if ([device[@"min"] isKindOfClass:[NSNumber class]]) minLen = [device[@"min"] integerValue];

    NSString *title = confirming ? @"Повторите пароль" : @"Новый пароль стирания";
    NSString *hint = confirming
        ? @"Введите его ещё раз, чтобы подтвердить."
        : [NSString stringWithFormat:@"Не менее %ld символов. Формат устройства: %@.", (long)minLen, type];

    UIAlertController *alert = [UIAlertController alertControllerWithTitle:title
                                                                    message:hint
                                                             preferredStyle:UIAlertControllerStyleAlert];
    Vo1dekAddPasswordField(alert, @"Пароль");
    [alert addAction:[UIAlertAction actionWithTitle:@"Отмена" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:confirming ? @"Сохранить" : @"Далее"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        NSString *password = alert.textFields.firstObject.text ?: @"";
        // See the note in Vo1dekPromptAndMaybeWipe: the follow-up runs on the
        // next main-queue turn so this alert has finished dismissing.
        dispatch_async(dispatch_get_main_queue(), ^{
            if (password.length < (NSUInteger)minLen) {
                Vo1dekShowNotice(@"Слишком короткий", @"Пароль короче минимальной длины для этого устройства.");
                return;
            }
            if (!confirming) {
                Vo1dekPromptForNewPassword(YES, password);
            } else if (![firstEntry isEqualToString:password]) {
                Vo1dekLog(@"[pref] confirmation mismatch");
                Vo1dekShowNotice(@"Не совпадает", @"Пароли различаются.");
            } else {
                Vo1dekStorePassword(password);
            }
        });
    }]];


    UIViewController *presenter = Vo1dekTopViewController();
    if (presenter == nil) return;
    [presenter presentViewController:alert animated:YES completion:nil];
}

#pragma mark - web view bridge

@interface Vo1dekBridge : NSObject <WKScriptMessageHandler>
@end

@implementation Vo1dekBridge

+ (instancetype)shared {
    static Vo1dekBridge *shared;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ shared = [Vo1dekBridge new]; });
    return shared;
}

- (void)userContentController:(WKUserContentController *)controller
      didReceiveScriptMessage:(WKScriptMessage *)message {
    if (![message.name isEqualToString:@"vo1dek"]) return;

    // Only our own pane may drive this; a message from any other Settings web
    // view is ignored outright.
    NSString *url = @"";
    if ([message respondsToSelector:@selector(webView)]) {
        url = message.webView.URL.absoluteString ?: @"";
    }
    if (strstr(url.UTF8String, Vo1dekPaneMarker) == NULL) {
        Vo1dekLog(@"[pref] rejected message from unexpected pane: %@", url);
        return;
    }

    NSDictionary *body = [message.body isKindOfClass:[NSDictionary class]] ? message.body : @{};
    NSString *action = body[@"action"];
    Vo1dekLog(@"[pref] action=%@", action);

    if ([action isEqualToString:@"status"]) {
        Vo1dekSendStatus();
    } else if ([action isEqualToString:@"setPassword"]) {
        Vo1dekPromptForNewPassword(NO, nil);
    } else if ([action isEqualToString:@"clear"]) {
        Vo1dekClearPassword();
    } else if ([action isEqualToString:@"wipe"]) {
        Vo1dekPromptAndMaybeWipe();
    }
}

@end

static WKWebView *Vo1dekFindWebView(UIView *view) {
    if ([view isKindOfClass:[WKWebView class]]) return (WKWebView *)view;
    for (UIView *sub in view.subviews) {
        WKWebView *found = Vo1dekFindWebView(sub);
        if (found) return found;
    }
    return nil;
}

// Settings hosts every plugin pane in a WKWebView, so "has a web view" is not
// specific enough. Our pane is the one whose URL lives inside our own bundle.
static BOOL Vo1dekIsOurPane(WKWebView *pane) {
    NSString *url = pane.URL.absoluteString;
    if (url.length == 0) return NO;
    return [url rangeOfString:@(Vo1dekPaneMarker)].location != NSNotFound;
}

// Takes `id` because the hooked class is a private type we never declare, so the
// compiler sees it as distinct from UIViewController and rejects the conversion.
static void Vo1dekAttachBridge(id controller) {
    WKWebView *pane = Vo1dekFindWebView(((UIViewController *)controller).view);
    if (pane == nil) return;
    if (!Vo1dekIsOurPane(pane)) return;

    Vo1dekPaneWebView = pane;
    @try {
        // Throws when a handler under this name is already registered, which is
        // the case we want to skip on repeat appearances.
        [pane.configuration.userContentController addScriptMessageHandler:Vo1dekBridge.shared name:@"vo1dek"];
        Vo1dekLog(@"[pref] bridge attached to pane");
    } @catch (NSException *e) {
        return;
    }

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.6 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        Vo1dekSendStatus();
    });
}

#pragma mark - hooks

%group Vo1dekPaneHooks

// Hooking UIViewController rather than PSWebViewController: the private class was
// reported missing at load time, because Settings pulls its plugin classes in
// lazily and our dylib is constructed before that happens. UIViewController is
// always resident, and the bundle-marker check above keeps the hook inert for
// every other Settings pane. viewDidAppear: is used because the pane's URL is
// still unset during viewDidLoad.
%hook UIViewController
- (void)viewDidLoad {
    %orig;
    Vo1dekAttachBridge(self);
}

- (void)viewDidAppear:(BOOL)animated {
    %orig;
    Vo1dekAttachBridge(self);
}

%end

%end

#pragma mark - result notification

static const void *Vo1dekPrefToken;

static void Vo1dekResultCallback(CFNotificationCenterRef center, void *observer,
                                CFStringRef name, const void *object, CFDictionaryRef userInfo) {
    dispatch_async(dispatch_get_main_queue(), ^{
        NSDictionary *result = Vo1dekReadPlist(VO1DEK_RESULT) ?: @{};
        Vo1dekLog(@"[pref] result ok=%@ method=%@ error=%@", result[@"ok"], result[@"method"], result[@"error"]);
        Vo1dekSendStatus();
    });
}

%ctor {
    @autoreleasepool {
        Vo1dekEnsureDir();

        // No class-existence gate here: the private pane controller is loaded
        // lazily by Settings and is reliably absent this early, which used to
        // skip hook installation entirely and leave the pane with no bridge.
        %init(Vo1dekPaneHooks);

        CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(),
                                        Vo1dekPrefToken,
                                        Vo1dekResultCallback,
                                        (__bridge CFStringRef)VO1DEK_NOTIFY_RESULT,
                                        NULL,
                                        CFNotificationSuspensionBehaviorCoalesce);
        Vo1dekLog(@"[pref] Settings half loaded");

        // The pane did not appear last round, and the absence of the line above
        // from probe.log suggests this dylib may not be loading at all. Record
        // what is actually on disk and whether the bundle parses, so the next
        // round tells us which half is broken instead of us guessing.
        NSBundle *self = [NSBundle bundleForClass:[Vo1dekBridge class]];
        Vo1dekLog(@"[pref] dylib path: %@", self.bundlePath ?: @"(unknown)");
        NSString *paneBundle = @"/var/jb/Library/PreferenceBundles/WipeCode.bundle";
        BOOL isDir = NO;
        BOOL exists = [[NSFileManager defaultManager] fileExistsAtPath:paneBundle isDirectory:&isDir];
        Vo1dekLog(@"[pref] pane bundle exists=%d dir=%d at %@", (int)exists, (int)isDir, paneBundle);
        for (NSString *name in @[@"Info.plist", @"Root.plist", @"pane.html"]) {
            NSString *path = [paneBundle stringByAppendingPathComponent:name];
            BOOL f = [[NSFileManager defaultManager] fileExistsAtPath:path];
            Vo1dekLog(@"[pref]   %@ present=%d", name, (int)f);
        }
        NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:
                              [paneBundle stringByAppendingPathComponent:@"Info.plist"]];
        Vo1dekLog(@"[pref] Info.plist parsed=%d keys=%@", (int)(info != nil), info.allKeys);
        NSDictionary *root = [NSDictionary dictionaryWithContentsOfFile:
                              [paneBundle stringByAppendingPathComponent:@"Root.plist"]];
        Vo1dekLog(@"[pref] Root.plist parsed=%d specifiers=%lu", (int)(root != nil),
                  (unsigned long)[root[@"PreferenceSpecifiers"] count]);
    }
}
