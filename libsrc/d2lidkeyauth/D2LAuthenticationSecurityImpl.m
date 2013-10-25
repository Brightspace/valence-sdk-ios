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

#import "D2LAuthenticationSecurityImpl.h"
#import "D2LSecurityHelper.h"
#import "D2LOperationSecurityImpl.h"

static NSString * const kSCHEME = @"https";
static NSString * const kAPP_ID_NAME = @"x_a";
static NSString * const kAPP_SIG_NAME = @"x_b";
static NSString * const kCALLBACK_NAME = @"x_target";
static NSString * const kTYPE_NAME = @"type";
static NSString * const kTYPE_VAL = @"mobile";
static NSString * const kPATH_TO_AUTH = @"/d2l/auth/api/token";

static NSString * const kAUTH_URL_TEMPLATE = @"%1$@://%2$@%3$@?%4$@"; //scheme, host, path, query


static NSString * const kCALLBACK_USER_ID_NAME = @"x_a";
static NSString * const kCALLBACK_USER_KEY_NAME = @"x_b";



@implementation D2LAuthenticationSecurityImpl

- (id)initWithAppID:(NSString *)appID andAppKey:(NSString *)appKey andHost:(NSString *)host withEncryptionRequired:(bool)encryptionRequired;
{
    self = [super init];
    if (self)
    {
        mAppID  = [appID copy];
        mAppKey = [appKey copy];
        mHost   = [host copy];
        mEncryptionRequired = encryptionRequired;
    }
    return self;
}
- (void)dealloc
{
    [mAppID release], mAppID = nil;
    [mAppKey release], mAppKey = nil;
    [mHost release], mHost = nil;
    [super dealloc];
}

- (NSURL *)createAuthenticationWebURLWithCallbackURL:(NSURL *)resultURI
{
    return [self createAuthenticationWebURLWithCallbackURL:resultURI useHTTPS:YES];
}


- (NSURL *)createAuthenticationWebURLWithCallbackURL:(NSURL *)resultURI useHTTPS:(bool)useHTTPS
{
    

    NSString *resultURLString = [resultURI absoluteString];
    
    NSString *sig = [D2LSecurityHelper performSignature:resultURLString key:mAppKey];
    
    
    
    NSMutableDictionary *queryParms = [NSMutableDictionary dictionaryWithCapacity:4];
    
    [queryParms setObject:mAppID  forKey:kAPP_ID_NAME ];
    [queryParms setObject:sig  forKey:kAPP_SIG_NAME ];
    [queryParms setObject:resultURLString  forKey:kCALLBACK_NAME ];
    [queryParms setObject:kTYPE_VAL  forKey:kTYPE_NAME ];
    
    NSString *queryString = [D2LSecurityHelper queryStringFromParameterDictionary:queryParms];
    
    NSString *authURLString = [NSString stringWithFormat: kAUTH_URL_TEMPLATE
                                                        , useHTTPS ? @"https" : @"http"
                                                        , mHost
                                                        , kPATH_TO_AUTH
                                                        , queryString];
                                
                                
    
    NSURL *authURL = [NSURL URLWithString:authURLString];
    return authURL;
}



- (id <D2LOperationSecurity>)createOperationContextFromResult:(NSURL *)resultURI{
    NSString *userID; 
    NSString *userKey;
    
    NSString *queryString = [resultURI query];
    
    NSDictionary *queryPairs = [D2LSecurityHelper queryParameterDictionaryFromNSString:queryString];
    
    userID  = [queryPairs objectForKey:kCALLBACK_USER_ID_NAME];
    userKey = [queryPairs objectForKey:kCALLBACK_USER_KEY_NAME];
    
    if ((userID== nil) || (userKey == nil))
    {
        return nil;
    }
    
    D2LOperationSecurityImpl *opSecurity = [[D2LOperationSecurityImpl alloc] initWithUserID:userID 
                                                                            andUserKey:userKey 
                                                                            andAppID: mAppID 
                                                                            andAppKey: mAppKey 
                                                                            andHost:mHost 
                                                                            withEncryptionRequirement:mEncryptionRequired];
    
    
    return [opSecurity autorelease];
}


- (id<D2LOperationSecurity>)createOperationContextFromUserID:(NSString *)userID andUserKey:(NSString *)userKey andServerSkewMillis:(long)serverSkewMillis;




{
        D2LOperationSecurityImpl *opSecurity = [[D2LOperationSecurityImpl alloc] initWithUserID:userID 
                                                                                  andUserKey:userKey 
                                                                                    andAppID: mAppID 
                                                                                   andAppKey: mAppKey 
                                                                                     andHost:mHost 
                                                                   withEncryptionRequirement:mEncryptionRequired];
    
    
        return [opSecurity autorelease];
}




@end
