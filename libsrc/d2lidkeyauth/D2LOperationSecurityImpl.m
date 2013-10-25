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


#import "D2LOperationSecurityImpl.h"
#import "D2LSecurityHelper.h"


static NSString * const kENCRYPED_SCHEME = @"https";
static NSString * const kPLAIN_SCHEME = @"http";

static NSString * const kBASE_STRING_TEMPLATE = @"%1$@&%2$@&%3$@"; //uppercase METHOD, lowercase PATH, timestamp as string 

static NSString * const kAPP_ID_QUERY_NAME = @"x_a";
static NSString * const kAPP_SIG_QUERY_NAME = @"x_c";
static NSString * const kUSER_ID_QUERY_NAME = @"x_b";
static NSString * const kUSER_SIG_QUERY_NAME = @"x_d";
static NSString * const kTIMESTAMP_QUERY_NAME = @"x_t";

static NSString * const kURL_TEMPLATE = @"%1$@://%2$@%3$@?%4$@"; //scheme, host, path, query  

static NSString * const kTIMESTAMP_ERROR_MESSAGE = @"Timestamp out of range";


@implementation D2LOperationSecurityImpl

@synthesize serverSkewMillis = mServerSkewMillis;

-(id)initWithUserID: (NSString *) userID andUserKey: (NSString *) userKey andAppID: (NSString *) appID andAppKey: (NSString *) appKey andHost: (NSString *) host withEncryptionRequirement: (BOOL) encryptOperations
{
    self = [super init];
    if (self)
    {
        mUserID     = [userID copy];
        mUserKey    = [userKey copy];
        mAppID      = [appID copy];
        mAppKey     = [appKey copy];
        mHostName   = [host copy];
        mEncryptOperationsFlag= encryptOperations;
        mServerSkewMillis = 0.0f;
    }
    return self;
}
-(void)dealloc
{
    [mUserID release], mUserID = nil;
    [mUserKey release], mUserKey = nil;
    [mAppID release], mAppID = nil;
    [mAppKey release], mAppKey = nil;
    [mHostName release], mHostName  = nil;
    [super dealloc];
}

- (void)encryptOperations:(BOOL)encrypt
{
    mEncryptOperationsFlag= encrypt;   
}


-(NSMutableURLRequest *) createAuthenticatedUriFromPath:(NSString *) path andMethod: (NSString*) httpMethod withQueryParameters: (NSDictionary *) parms
{
    double timestampSecondsDouble = [[NSDate date] timeIntervalSince1970];
    
    double timestampAdjustedSeconds = ((double)(timestampSecondsDouble)) + ((double)(mServerSkewMillis));
    NSString * timestampAdjustedSecondsString = [NSString stringWithFormat:@"%.0f", timestampAdjustedSeconds];
    httpMethod = [httpMethod uppercaseString];
    NSString * pathLower = [path lowercaseString];
    NSString * signatureBaseString = [NSString stringWithFormat: kBASE_STRING_TEMPLATE, httpMethod, pathLower, timestampAdjustedSecondsString];
    
    
    NSString * appSig = [D2LSecurityHelper performSignature:signatureBaseString key:mAppKey];
    NSString * userSig = [D2LSecurityHelper performSignature:signatureBaseString key:mUserKey]; 
    if ((appSig == nil) || (userSig == nil))
    {
        return nil;
    }
    
    NSMutableDictionary * queryParm = [NSMutableDictionary dictionaryWithDictionary:parms]; //initialize with existing values
    [queryParm setObject: mAppID forKey:kAPP_ID_QUERY_NAME];
    [queryParm setObject: appSig forKey:kAPP_SIG_QUERY_NAME];
    [queryParm setObject: mUserID forKey:kUSER_ID_QUERY_NAME];
    [queryParm setObject:userSig forKey:kUSER_SIG_QUERY_NAME];
    [queryParm setObject:timestampAdjustedSecondsString forKey:kTIMESTAMP_QUERY_NAME];
     
    NSString * queryString = [D2LSecurityHelper queryStringFromParameterDictionary:queryParm];
    NSString * scheme = mEncryptOperationsFlag?kENCRYPED_SCHEME:kPLAIN_SCHEME;
    NSString * uriToReturnString = [NSString stringWithFormat:kURL_TEMPLATE 
                                                            ,scheme
                                                            ,mHostName
                                                            ,path
                                                            ,queryString];
    
    //NSLog(@"%@",uriToReturnString);
    NSURL * uriToReturn = [NSURL URLWithString:uriToReturnString];
    NSMutableURLRequest * requestToReturn = [NSMutableURLRequest requestWithURL:uriToReturn];
    [requestToReturn setHTTPMethod:httpMethod];
    return requestToReturn;
   
}

-(D2LOperationResult)handleResponseWithHTTPCode: (int) resultCode andBody: (NSInputStream *)is andLogMessagesResult: (NSString**) logMessage;
{
    
    if (resultCode == 200) {return kD2L_OP_RESULT_OKAY; } //avoid reading the stream, caller cares about contents
   
    //Read the result body InputStream into an NSData and covert that to an NSString
    const unsigned int bufSize = 512;
    uint8_t buf[bufSize];      
    int bytesRead = 0;
    NSMutableData *data = [[[NSMutableData alloc] init] autorelease];

    do {
        bytesRead = [is read:buf maxLength:bufSize]; 
        [data appendBytes:(void*)buf length:bytesRead];
    }while (bytesRead > 0);
    
    NSString *resultBody = [[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] autorelease];     
    
    switch (resultCode)
    {
            
        case 401:  //not authorized, key and id may no be invalid, try again
            return kD2L_OP_RESULT_INVALID_SIG; 
            
        case 403: //forbidden
            if([resultBody hasPrefix:kTIMESTAMP_ERROR_MESSAGE]){
                NSArray *responseParts = [resultBody componentsSeparatedByCharactersInSet:
                                          [NSCharacterSet newlineCharacterSet]];
                @try {
                    NSString *serverStampString = [responseParts objectAtIndex:1];
                    double serverStamp = [serverStampString doubleValue];
                    self.serverSkewMillis = serverStamp - [[NSDate date] timeIntervalSince1970];
                } //Catches NSRangeException...
                @catch (NSException *exception) {
                    *logMessage = [NSString stringWithString:@"Invalid Timestamp response format.  Unable to set skew."];
                }
                @finally {
                    return kD2L_OP_RESULT_INVALID_TIMESTAMP;
                }
            }
            //TODO: Future - check for JSON formatted Timestamp message
            //if([resultBody isParsableJson])Check it for the timestampe fields....
            
            return kD2L_OP_RESULT_NO_PERMISSION;
    }
    
    return kD2L_OP_RESULT_UNKNOWN;
    
}

-(NSString*) userID
{
    return mUserID;
}

-(NSString *) userKey
{
    return mUserKey;
}

-(NSString *)hostName
{
    return mHostName;
}

@end
