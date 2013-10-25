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
#import "D2LOperationSecurity.h"


@interface D2LOperationSecurityImpl : NSObject <D2LOperationSecurity> {
    NSString * mUserID;
    NSString * mUserKey;
    NSString * mAppID; 
    NSString * mAppKey;
    BOOL mEncryptOperationsFlag; 
    NSString * mHostName;
    double mServerSkewMillis;
    
        
    
}


- (void)encryptOperations:(BOOL)encrypt;

-(id)initWithUserID: (NSString *) userID andUserKey: (NSString *) userKey andAppID: (NSString *) appID andAppKey: (NSString *) appKey andHost: (NSString *) host withEncryptionRequirement: (BOOL) encryptOperations;
-(void)dealloc;

-(NSMutableURLRequest *) createAuthenticatedUriFromPath:(NSString *) path andMethod: (NSString*) httpMethod withQueryParameters: (NSDictionary *) parms;
-(D2LOperationResult)handleResponseWithHTTPCode: (int) resultCode andBody: (NSInputStream *)is andLogMessagesResult: (NSString**) logMessage;
-(NSString*) userID;
-(NSString *) userKey;
@property (readwrite, assign) double serverSkewMillis;
-(NSString *)hostName;


@end



