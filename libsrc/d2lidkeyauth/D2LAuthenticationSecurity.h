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

/**
 * Performs operations related to app level security.
 *
 *
 */


@protocol D2LAuthenticationSecurity <NSObject>




    
    /**
     * Using the application id and key passed from D2LSecurityFactory at instantiation time
     * and the callback uri this object will create a uri properly signed to request authentication and authorization
     * In a browser window. Native apps must be able to intercept the uri provided.  
     *
     * @param resultURI - a call back uri that will be invoked by the browser, it will have additional parameters
     * appended to the query string when the user has authenticated and authorized this application.
     *
     * @param useHTTPS - specifies whether to prefix the NSURL with HTTP:// or HTTPS:// .  The default behavior
     *                   YES.
     *
     * @return uri object to open in a browser.
     */
    
    
- (NSURL *) createAuthenticationWebURLWithCallbackURL:(NSURL *)resultURI;
- (NSURL *)createAuthenticationWebURLWithCallbackURL:(NSURL *)resultURI useHTTPS:(bool)useHTTPS;

    /**
     * This method should be called when the resultURL from a call to createWebURLForAuthentication is received.
     * It will extract the user specific id and key and create a D2LOperationSecurity object that can be used to
     * generate subsequent calls.
     *
     * @param resultURL - the uri as received from the browser, this will be the same as the uri passed to createAuthenticationWebURL
     * but with a user specific field values
     * @param hostName - the host that was originally logged into (host pass to to createWebURLForAuthentication)
     * @param encryptOperations - true if ssl should be used
     *
     * @return a D2LOperationSecurity object to be used to sign API requests in the users context.
     *
     */
    
-(id <D2LOperationSecurity>) createOperationContextFromResult:(NSURL *) resultURI ;
    
    /**
     * This method should be called from non interactive components or on interactive components that already
     * have determined a userID and userKey that they want to use. (These values can be extracted from D2LOperationSecurity
     * objects and retained between instantiations of apps).
     *
     * @param userID - id returned from saving state of D2LOperationSecurity
     * @param userKey - key returned from saving state of D2LOperationSecurity 
     * @param serverSkewMillis - server clock skew returned from saving state of D2LOperationSecurity
     
     * @return  a D2LOperationSecurity object to be used to sign API requests in the users context.
     */
-(id<D2LOperationSecurity>) createOperationContextFromUserID: (NSString *) userID andUserKey: (NSString *) userKey andServerSkewMillis:(long) serverSkewMillis;

    
    



@end
