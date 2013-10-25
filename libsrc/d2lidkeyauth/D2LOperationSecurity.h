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

/**
 * Type and constants used for checking results of operations
 */


typedef enum {
    /**
     *
     * Returned when no result can be identified or as an unitialized value. Val=0x00;
     */
    kD2L_OP_RESULT_UNKNOWN = 0x00,
    
    /**
     *
     * Returned when result 200 okay. Val=0x01
     */
    kD2L_OP_RESULT_OKAY = 0x01,
    
    /**
     * Returned when the signature or id was invalid, typically this should trigger a reauthentication. Val=0x02
     */
    kD2L_OP_RESULT_INVALID_SIG = 0x02,
    /**
     * Returned if the timestamp was outside of the validity window, this indicates clocks are skewed. The handleResult
     * message automatically corrects the clock so on receiving this message callers typically should retry the same operation. Val=0x03
     */
    kD2L_OP_RESULT_INVALID_TIMESTAMP = 0x03,
    /**
     * Returned if the requested operation is not allowed, typically user should be prompted that they need to request
     * different permissions from the administrator. Val = 0x04
     */
    kD2L_OP_RESULT_NO_PERMISSION = 0x04,
    
    /**
     * Returned if the requested operation fails in a non-recoverable (non retry) way. 
     * Callers should log the message returned from the logmessages parameter to diagnose.
     * Val = 0x05
     */
    kD2L_OP_RESULT_GENERAL_ERROR = 0x05,
    
    
} D2LOperationResult;    




/**
 * Performs operations related to making secure calls to server operation in the specific context of a user.
 *
 * Also provides helper tools to deal with protocol error results
 *
 */


@protocol D2LOperationSecurity <NSObject>


/**
 * Called to enable/disable HTTPS
 *
 * @param enable
 */
- (void)encryptOperations:(BOOL)encrypt;

/**
 * Called to create a uri using the path specified and the host this object was created for.
 * This call also adds d2l authentication parameters
 * The method and the path can not change without affecting the signature, but, query string parameters
 * can be added after creating and signing the Uri by changing the returned uri.
 *
 * @param path
 * @param httpMethod
 * @param parms - string to string dictionary unencoded to be appended as query parms
 * @return
 */
-(NSMutableURLRequest *) createAuthenticatedUriFromPath:(NSString *) path andMethod: (NSString*) httpMethod withQueryParameters: (NSDictionary *) parms;



/**
 * This utility method can be used to process results from the server, it interprets http result code and
 * optional body messages on error (e.g. distinguishing timestamp skew from bad signature). In addition,
 * in the special case of timestamp skew this method will update the internal skew so that the next request
 * should avoid this error.
 * @param resultCode - http result code, can include the successful result of 2XX in which case the stream is not read
 * @param is - input stream from the http connection,
 * @param logMessageArray - if null, this parameter is ignored, if not null and there is a log worthy message an NSString
 *                              object is created with the log message and returned autoreleased.
 
 * @return one of the RESULT_* results from this interface. Most commonly applications will minimally want to check
 * for RESULT_OKAY in order to proceed with interpretting results.
 */
-(D2LOperationResult)handleResponseWithHTTPCode: (int) resultCode andBody: (NSInputStream *)is andLogMessagesResult: (NSString**) logMessage;


/**
 * Apps can retrieve this value on exit and use on next execution in order to resume the app as this user.
 * @return userID
 */
-(NSString*) userID;
/**
 * Apps can retrieve this value on exit and use on next execution in order to resume the app as this user.
 * @return
 */

-(NSString *) userKey;

/**
 *  Apps can retrieve this value on exit and set on launch in order to avoid resyncing clock when launching. 
 *
 * This property is typically only used on startup as the handleResponse call automatically
 * fixes clock skew.
 */

@property (readwrite, assign) double serverSkewMillis;


@end
