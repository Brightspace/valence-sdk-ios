//Copyright 2011 Desire2Learn Incorporated
//
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//http://www.apache.org/licenses/LICENSE-2.0
//
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//See the License for the specific language governing permissions and
//limitations under the License.

#import "D2LSecurityFactory.h"
#import "D2LAuthenticationSecurityImpl.h"

@implementation D2LSecurityFactory
+(id <D2LAuthenticationSecurity>)authenticationSecurityFromAppID: (NSString *) appID andAppKey: (NSString *) appKey  andHost: (NSString *) hostName withEncryptionRequirement: (BOOL) encryptOperations
{
    D2LAuthenticationSecurityImpl * appSecurity = [[D2LAuthenticationSecurityImpl alloc] initWithAppID: appID andAppKey: appKey andHost:hostName withEncryptionRequired:encryptOperations];
    [appSecurity autorelease];
    
    return appSecurity;
}

@end
