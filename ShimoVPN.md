# Shimo 5.0.4 - Privilege Escalation 

In the Shimo VPN client in version 5.0.4 on macOS, 
the com.feingeist.shimo.helper tool LaunchDaemon implements an unprotected XPC service that can be abused to execute scripts as root.

When a client connects to the service the incomming connection is verified using `processIdentifier` instead of `audit_token`. Such a mechanism is prone to `PID reuse` attack. During this attack it is possible to impersonate a legitimate client and use all methods offered by `ShimoHelperToolProtocol` protocol. 

Vulnerable method: 
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

Once the 



## Recommendation 


