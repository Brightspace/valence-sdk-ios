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

#import "D2LSecurityHelper.h"
#import "base64.h"
#import <CommonCrypto/CommonHMAC.h>

@implementation D2LSecurityHelper




+(NSDictionary *) queryParameterDictionaryFromNSString: (NSString *) queryString  {
    NSArray * parameterList = [queryString componentsSeparatedByString:@"&"];
    
    int maxOffset;
    int i;
    maxOffset = [parameterList count] - 1;
    NSMutableDictionary * paramDictionary = [[NSMutableDictionary alloc] initWithCapacity: maxOffset + 1];
    for (i = 0; i <= maxOffset; i++)
    {
        NSString * param = [parameterList objectAtIndex: i];
        NSArray * paramPair = [param componentsSeparatedByString:@"="];
        NSString * paramName = [paramPair objectAtIndex: 0];
        NSString * paramValue = nil; 
        if ([paramPair count] == 2 ) 
        {
            paramValue = [paramPair objectAtIndex: 1];
        }
        else 
        {
            continue; //NOTE: this means parameters without values in query string are ignored.
        }
        paramName = [paramName stringByReplacingPercentEscapesUsingEncoding:NSUTF8StringEncoding];
        paramValue = [paramValue stringByReplacingPercentEscapesUsingEncoding:NSUTF8StringEncoding];
        
        [paramDictionary setValue:paramValue forKey:paramName];
        
    }
    return [paramDictionary autorelease];
}


const static int ESCAPED_CHAR_BUFF_SIZE = 4;

+ (NSString *) decentURLEncoding: (NSString *) stringToEncode
{
    char const * stringToEncodeUTF8 = [stringToEncode cStringUsingEncoding: NSUTF8StringEncoding];
    char const * ESCAPE_TEMPLATE = "%%%.2x"; //for %xx
    
    char escapedChar[ESCAPED_CHAR_BUFF_SIZE];
    
    int lengthOfInput = strlen(stringToEncodeUTF8);
    int maximumLenthOfOutput = 3*lengthOfInput;
    char * outputCString = malloc(maximumLenthOfOutput);
    if (outputCString == nil)
    {
        return @"";
    }
    
    int i;
    char charAtI;
    int outputOffset = 0;
    int returnVal = 0;
    
    for (i = 0; i < lengthOfInput; i++) {
        charAtI = stringToEncodeUTF8[i];
        if ( isdigit(charAtI) || isalpha(charAtI) || charAtI == '.' || charAtI == '_' || charAtI == '-'  ) {
            outputCString[outputOffset] = charAtI;
            outputOffset +=1;
        }
        else {
            returnVal = snprintf(escapedChar, ESCAPED_CHAR_BUFF_SIZE, ESCAPE_TEMPLATE, charAtI);
            if (returnVal < 0) {
                free(outputCString);
                return @"";
            }
            outputCString[outputOffset] = escapedChar[0];
            outputCString[outputOffset+1] = escapedChar[1];
            outputCString[outputOffset+2] = escapedChar[2];
            outputOffset += 3;
        }
    }
    outputCString[outputOffset] = '\0';
    NSString * outputString = [NSString stringWithCString:outputCString encoding:NSUTF8StringEncoding]; //in actuality the resulting string can be equivalently interpreted as ascii rather than utf8   
    free(outputCString);
    return outputString;
}


+ (NSString *) performSignature: (NSString *) stringToSign key: (NSString *) key  {
    const char * stringToSignUTF8 = [stringToSign cStringUsingEncoding:NSUTF8StringEncoding];
    const char * keyUTF8 = [key cStringUsingEncoding:NSUTF8StringEncoding];
    
    int stringToSignLength = strlen(stringToSignUTF8);
    int keyLength = strlen(keyUTF8);
    
    unsigned char hmacSha256Signature[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, keyUTF8, keyLength, stringToSignUTF8, stringToSignLength, hmacSha256Signature);
    
    char textSigBuffer[CC_SHA256_DIGEST_LENGTH*2]; //only require room for 4/3 expansion,
    Base64encode(textSigBuffer, (char const *)hmacSha256Signature, CC_SHA256_DIGEST_LENGTH);    
    
    NSString * stringToReturn = [NSString stringWithCString:textSigBuffer encoding:NSASCIIStringEncoding];
    
    return stringToReturn;
}

+(NSString *) queryStringFromParameterDictionary: (NSDictionary *) parameterDictionary
{
    NSMutableString * stringToReturn = [[NSMutableString alloc] init];
    [stringToReturn autorelease];
    
    NSEnumerator * keyEnum = [parameterDictionary keyEnumerator];
    NSString * queryKey = nil;
    NSString * queryVal = nil;
    while( (queryKey = (NSString *)[keyEnum nextObject] ) != nil)
    {
        queryVal = (NSString *)[parameterDictionary objectForKey: queryKey];
    
        queryKey = [D2LSecurityHelper decentURLEncoding: queryKey];
        queryVal = [D2LSecurityHelper decentURLEncoding: queryVal];
        [stringToReturn appendString: @"&"];
        [stringToReturn appendString: queryKey];
        [stringToReturn appendString: @"="];
        [stringToReturn appendString: queryVal];

        
    }
    NSString * nsstringToReturn = nil;
    if ([stringToReturn length] > 0) // if we added anything, we will have a leading ampersand
    {
        
        nsstringToReturn = [stringToReturn substringFromIndex: 1];
    }
    
    return nsstringToReturn;
}



@end
