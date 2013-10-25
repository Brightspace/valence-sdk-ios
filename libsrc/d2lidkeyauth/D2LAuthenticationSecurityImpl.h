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

#import <Foundation/Foundation.h>
#import "D2LAuthenticationSecurity.h"

@interface D2LAuthenticationSecurityImpl : NSObject <D2LAuthenticationSecurity>{
    NSString *mAppID;
    NSString *mAppKey;
    NSString *mHost;
    bool mEncryptionRequired;
}


- (id)initWithAppID:(NSString *)appID
         andAppKey:(NSString *)appKey 
           andHost:(NSString *)host
withEncryptionRequired:(bool)encryptionRequired;

- (void)dealloc;
//Implementation from D2LAuthenticationSecurity


- (NSURL *)createAuthenticationWebURLWithCallbackURL:(NSURL *)resultURI;

- (id <D2LOperationSecurity>)createOperationContextFromResult:(NSURL *)resultURI ;

- (id<D2LOperationSecurity>)createOperationContextFromUserID: (NSString *)userID andUserKey: (NSString *)userKey andServerSkewMillis:(long)serverSkewMillis;






@end
