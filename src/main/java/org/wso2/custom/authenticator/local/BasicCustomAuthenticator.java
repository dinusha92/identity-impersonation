/*
* Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
*
* WSO2 Inc. licenses this file to you under the Apache License,
* Version 2.0 (the "License"); you may not use this file except
* in compliance with the License.
* You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing,
* software distributed under the License is distributed on an
* "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
* KIND, either express or implied.  See the License for the
* specific language governing permissions and limitations
* under the License.
*/
package org.wso2.custom.authenticator.local;

import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticator;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Username Password based custom Authenticator for impersonation
 */
public class BasicCustomAuthenticator extends BasicAuthenticator {


    private static final long serialVersionUID = 4345354156955223654L;
    private static final Log log = LogFactory.getLog(BasicCustomAuthenticator.class);
    private static final String DEFAULT_IMP_ADMIN_ROLE = "Internal/impadmin";
    private static final String DEFAULT_IMP_USER_ROLE = "Internal/impuser";
    private static final String IMPERSONATEE = "impersonatee";
    private static final String IMP_ADMIN_ROLE = "IMP_ADMIN";
    private static final String IMP_USER_ROLE = "IMP_USER";


    @Override public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response,
            AuthenticationContext context) throws AuthenticationFailedException, LogoutFailedException {
        //check if it is a logout request
        if (context.isLogoutRequest()) {
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        } else {
            //initial this as a usual basic authentication
            boolean impAuthentication = false;
            AuthenticatorFlowStatus authenticatorFlowStatus = null;
            //if impersonatee is present -> impersonation authentication
            if ((request.getParameter(IMPERSONATEE) != null) || context.getProperty(IMPERSONATEE) != null) {
                impAuthentication = true;
                //set it into context if it is not in the context
                if (context.getProperty(IMPERSONATEE) == null) {
                    context.setProperty(IMPERSONATEE, request.getParameter(IMPERSONATEE));
                }
                authenticatorFlowStatus = super.process(request, response, context);
            }
            if (impAuthentication) {
                //for the first time this will be INCOMPLETED because username & password = null
                if (authenticatorFlowStatus.equals(AuthenticatorFlowStatus.SUCCESS_COMPLETED)) {
                    //if the basic authentication is successful, get the authenticated user
                    AuthenticatedUser authenticatedUser = context.getSubject();
                    Map<String, String> configParams = getAuthenticatorConfig().getParameterMap();
                    try {
                        //get the uer real of the authenticated user
                        UserRealm realm = getUserRealm(authenticatedUser.getAuthenticatedSubjectIdentifier());
                        //get the roles of the authenticated user
                        String[] adminRoleList = realm.getUserStoreManager().getRoleListOfUser(MultitenantUtils
                                .getTenantAwareUsername(authenticatedUser.getAuthenticatedSubjectIdentifier()));
                        //check if the authenticated user has the impAdmin role
                        boolean hasRole = false;
                        String impAdminRole = configParams.get(IMP_ADMIN_ROLE);
                        if (impAdminRole == null || impAdminRole.isEmpty()) {
                            impAdminRole = DEFAULT_IMP_ADMIN_ROLE;
                        }
                        for (String role : adminRoleList) {
                            if (impAdminRole.equals(role)) {
                                hasRole = true;
                                break;
                            }
                        }

                        //if impersonate has the necessary role, then check impersonatee
                        if (hasRole) {
                            //get the impersonatee's roles
                            UserRealm impUserRealm = getUserRealm((String) context.getProperty(IMPERSONATEE));
                            String[] impUserRoles = impUserRealm.getUserStoreManager().getRoleListOfUser(MultitenantUtils
                                    .getTenantAwareUsername((String) context.getProperty(IMPERSONATEE)));

                            String impUserRole = configParams.get(IMP_USER_ROLE);
                            if (impUserRole == null || impUserRole.isEmpty()) {
                                impUserRole = DEFAULT_IMP_USER_ROLE;
                            }

                            for (String role : impUserRoles) {
                                //check if the impersonatee has the necessary role
                                if (impUserRole.equals(role)) {
                                    log.debug("Impersonatee is identified");
                                    //set subject as impersonatee
                                    AuthenticatedUser user = AuthenticatedUser
                                            .createLocalAuthenticatedUserFromSubjectIdentifier(
                                                    (String) context.getProperty(IMPERSONATEE));
                                    context.setSubject(user);
                                    return authenticatorFlowStatus;
                                }
                            }

                        }
                    } catch (org.wso2.carbon.user.api.UserStoreException e) {
                        String errorMessage = "Unable to get the user realm";
                        log.error(errorMessage, e);
                        throw new AuthenticationFailedException(errorMessage, e);
                    }
                    return authenticatorFlowStatus;
                } else { //if basic authentication is not success return its status
                    return authenticatorFlowStatus;
                }

            } else { //if it is not a impersonation activity
                return super.process(request, response, context);
            }
        }
    }


    @Override public String getFriendlyName() {
        return BasicCustomAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override public String getName() {
        return BasicCustomAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    /**
     * @param username
     * @return
     * @throws org.wso2.carbon.user.api.UserStoreException
     */
    private org.wso2.carbon.user.core.UserRealm getUserRealm(String username)
            throws org.wso2.carbon.user.api.UserStoreException {
        org.wso2.carbon.user.core.UserRealm userRealm;
        String tenantDomain = MultitenantUtils.getTenantDomain(username);
        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        RealmService realmService = IdentityTenantUtil.getRealmService();
        userRealm = (org.wso2.carbon.user.core.UserRealm) realmService.getTenantUserRealm(tenantId);
        return userRealm;
    }

}