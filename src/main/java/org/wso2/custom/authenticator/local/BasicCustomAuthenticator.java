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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.model.IdentityErrorMsgContext;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.custom.authenticator.local.internal.BasicCustomAuthenticatorServiceComponent;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

/**
 * Username Password based custom Authenticator
 */
public class BasicCustomAuthenticator extends AbstractApplicationAuthenticator
        implements LocalApplicationAuthenticator {


    private static final long serialVersionUID = 4345354156955223654L;
    private static final String PASSWORD_PROPERTY = "PASSWORD_PROPERTY";
    private static final String PASSWORD_RESET_ENDPOINT = "accountrecoveryendpoint/confirmrecovery.do?";
    private static final Log log = LogFactory.getLog(BasicCustomAuthenticator.class);
    private static String RE_CAPTCHA_USER_DOMAIN = "user-domain-recaptcha";
    private static final String IMP_ADMIN_ROLE = "Internal/impadmin";
    private static final String IMP_USER_ROLE = "Internal/impuser";
    private static final String IMPERSONATEE = "impersonatee";

    @Override public boolean canHandle(HttpServletRequest request) {
        String userName = request.getParameter(BasicCustomAuthenticatorConstants.USER_NAME);
        String password = request.getParameter(BasicCustomAuthenticatorConstants.PASSWORD);
        if (userName != null && password != null) {
            return true;
        }
        return false;
    }

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
                    try {
                        //get the uer real of the authenticated user
                        UserRealm realm = getUserRealm(authenticatedUser.getAuthenticatedSubjectIdentifier());
                        //get the roles of the authenticated user
                        String[] adminRoleList = realm.getUserStoreManager().getRoleListOfUser(MultitenantUtils
                                .getTenantAwareUsername(authenticatedUser.getAuthenticatedSubjectIdentifier()));
                        //check if the authenticated user has the impAdmin role
                        boolean hasRole = false;
                        for (String role : adminRoleList) {
                            if (IMP_ADMIN_ROLE.equals(role)) {
                                hasRole = true;
                                break;
                            }
                        }

                        //if impersonate has the necessary role, then check impersonatee
                        if (hasRole) {
                            //get the impersonatee's roles
                            UserRealm impUserRealm = getUserRealm((String) context.getProperty(IMPERSONATEE));
                            String[] impUserRole = impUserRealm.getUserStoreManager().getRoleListOfUser(MultitenantUtils
                                    .getTenantAwareUsername((String) context.getProperty(IMPERSONATEE)));
                            for (String role : impUserRole) {
                                //check if the impersonatee has the necessary role
                                if (IMP_USER_ROLE.equals(role)) {
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

    @Override protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
            AuthenticationContext context) throws AuthenticationFailedException {

        Map<String, String> parameterMap = getAuthenticatorConfig().getParameterMap();
        String showAuthFailureReason = null;
        if (parameterMap != null) {
            showAuthFailureReason = parameterMap.get("showAuthFailureReason");
            if (log.isDebugEnabled()) {
                log.debug("showAuthFailureReason has been set as : " + showAuthFailureReason);
            }
        }

        String loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL();
        String retryPage = ConfigurationFacade.getInstance().getAuthenticationEndpointRetryURL();
        String queryParams = context.getContextIdIncludedQueryParams();
        String password = (String) context.getProperty(PASSWORD_PROPERTY);
        context.getProperties().remove(PASSWORD_PROPERTY);

        try {
            String retryParam = "";

            if (context.isRetrying()) {
                retryParam = "&authFailure=true&authFailureMsg=login.fail.message";
            }

            if (context.getProperty("UserTenantDomainMismatch") != null && (Boolean) context
                    .getProperty("UserTenantDomainMismatch")) {
                retryParam = "&authFailure=true&authFailureMsg=user.tenant.domain.mismatch.message";
                context.setProperty("UserTenantDomainMismatch", false);
            }

            IdentityErrorMsgContext errorContext = IdentityUtil.getIdentityErrorMsg();
            IdentityUtil.clearIdentityErrorMsg();

            if (errorContext != null && errorContext.getErrorCode() != null) {
                if (log.isDebugEnabled()) {
                    log.debug("Identity error message context is not null");
                }
                String errorCode = errorContext.getErrorCode();

                if (errorCode.equals(IdentityCoreConstants.USER_ACCOUNT_NOT_CONFIRMED_ERROR_CODE)) {
                    retryParam = "&authFailure=true&authFailureMsg=account.confirmation.pending";
                    String username = request.getParameter(BasicCustomAuthenticatorConstants.USER_NAME);
                    Object domain = IdentityUtil.threadLocalProperties.get().get(RE_CAPTCHA_USER_DOMAIN);
                    if (domain != null) {
                        username = IdentityUtil.addDomainToName(username, domain.toString());
                    }

                    String redirectURL = response.encodeRedirectURL(loginPage + ("?" + queryParams))
                            + BasicCustomAuthenticatorConstants.FAILED_USERNAME + URLEncoder
                            .encode(username, BasicCustomAuthenticatorConstants.UTF_8)
                            + BasicCustomAuthenticatorConstants.ERROR_CODE + errorCode
                            + BasicCustomAuthenticatorConstants.AUTHENTICATORS + getName() + ":"
                            + BasicCustomAuthenticatorConstants.LOCAL + retryParam;
                    response.sendRedirect(redirectURL);

                } else if (errorCode
                        .equals(IdentityCoreConstants.ADMIN_FORCED_USER_PASSWORD_RESET_VIA_EMAIL_LINK_ERROR_CODE)) {
                    retryParam = "&authFailure=true&authFailureMsg=password.reset.pending";
                    String redirectURL = response.encodeRedirectURL(loginPage + ("?" + queryParams))
                            + BasicCustomAuthenticatorConstants.FAILED_USERNAME + URLEncoder
                            .encode(request.getParameter(BasicCustomAuthenticatorConstants.USER_NAME),
                                    BasicCustomAuthenticatorConstants.UTF_8)
                            + BasicCustomAuthenticatorConstants.ERROR_CODE + errorCode
                            + BasicCustomAuthenticatorConstants.AUTHENTICATORS + getName() + ":"
                            + BasicCustomAuthenticatorConstants.LOCAL + retryParam;
                    response.sendRedirect(redirectURL);

                } else if (errorCode
                        .equals(IdentityCoreConstants.ADMIN_FORCED_USER_PASSWORD_RESET_VIA_OTP_ERROR_CODE)) {
                    String username = request.getParameter(BasicCustomAuthenticatorConstants.USER_NAME);
                    String redirectURL = response.encodeRedirectURL((PASSWORD_RESET_ENDPOINT + queryParams))
                            + BasicCustomAuthenticatorConstants.USER_NAME + "=" + URLEncoder.encode(username)
                            + "&confirmation=" + password;
                    response.sendRedirect(redirectURL);

                } else if (showAuthFailureReason != null && "true".equals(showAuthFailureReason)) {

                    int remainingAttempts =
                            errorContext.getMaximumLoginAttempts() - errorContext.getFailedLoginAttempts();

                    if (log.isDebugEnabled()) {
                        log.debug("errorCode : " + errorCode);
                        log.debug("username : " + request.getParameter(BasicCustomAuthenticatorConstants.USER_NAME));
                        log.debug("remainingAttempts : " + remainingAttempts);
                    }

                    if (errorCode.equals(UserCoreConstants.ErrorCode.INVALID_CREDENTIAL)) {
                        retryParam = retryParam + BasicCustomAuthenticatorConstants.ERROR_CODE + errorCode
                                + BasicCustomAuthenticatorConstants.FAILED_USERNAME + URLEncoder
                                .encode(request.getParameter(BasicCustomAuthenticatorConstants.USER_NAME),
                                        BasicCustomAuthenticatorConstants.UTF_8) + "&remainingAttempts="
                                + remainingAttempts;
                        response.sendRedirect(response.encodeRedirectURL(loginPage + ("?" + queryParams))
                                + BasicCustomAuthenticatorConstants.AUTHENTICATORS + getName() + ":"
                                + BasicCustomAuthenticatorConstants.LOCAL + retryParam);
                    } else if (errorCode.equals(UserCoreConstants.ErrorCode.USER_IS_LOCKED)) {
                        String redirectURL = retryPage;
                        if (remainingAttempts == 0) {
                            redirectURL = response.encodeRedirectURL(redirectURL + ("?" + queryParams))
                                    + BasicCustomAuthenticatorConstants.ERROR_CODE + errorCode
                                    + BasicCustomAuthenticatorConstants.FAILED_USERNAME + URLEncoder
                                    .encode(request.getParameter(BasicCustomAuthenticatorConstants.USER_NAME),
                                            BasicCustomAuthenticatorConstants.UTF_8) + "&remainingAttempts=0";
                        } else {
                            redirectURL = response.encodeRedirectURL(redirectURL + ("?" + queryParams))
                                    + BasicCustomAuthenticatorConstants.ERROR_CODE + errorCode
                                    + BasicCustomAuthenticatorConstants.FAILED_USERNAME + URLEncoder
                                    .encode(request.getParameter(BasicCustomAuthenticatorConstants.USER_NAME),
                                            BasicCustomAuthenticatorConstants.UTF_8);
                        }
                        response.sendRedirect(redirectURL);

                    } else if (errorCode.equals(UserCoreConstants.ErrorCode.USER_DOES_NOT_EXIST)) {
                        retryParam = retryParam + BasicCustomAuthenticatorConstants.ERROR_CODE + errorCode
                                + BasicCustomAuthenticatorConstants.FAILED_USERNAME + URLEncoder
                                .encode(request.getParameter(BasicCustomAuthenticatorConstants.USER_NAME),
                                        BasicCustomAuthenticatorConstants.UTF_8);
                        response.sendRedirect(response.encodeRedirectURL(loginPage + ("?" + queryParams))
                                + BasicCustomAuthenticatorConstants.AUTHENTICATORS + getName() + ":"
                                + BasicCustomAuthenticatorConstants.LOCAL + retryParam);
                    } else if (errorCode.equals(IdentityCoreConstants.USER_ACCOUNT_DISABLED_ERROR_CODE)) {
                        retryParam = retryParam + BasicCustomAuthenticatorConstants.ERROR_CODE + errorCode
                                + BasicCustomAuthenticatorConstants.FAILED_USERNAME + URLEncoder
                                .encode(request.getParameter(BasicCustomAuthenticatorConstants.USER_NAME),
                                        BasicCustomAuthenticatorConstants.UTF_8);
                        response.sendRedirect(response.encodeRedirectURL(loginPage + ("?" + queryParams))
                                + BasicCustomAuthenticatorConstants.AUTHENTICATORS + getName() + ":"
                                + BasicCustomAuthenticatorConstants.LOCAL + retryParam);
                    } else if (errorCode
                            .equals(IdentityCoreConstants.ADMIN_FORCED_USER_PASSWORD_RESET_VIA_OTP_MISMATCHED_ERROR_CODE)) {
                        retryParam = "&authFailure=true&authFailureMsg=login.fail.message";
                        String redirectURL = response.encodeRedirectURL(loginPage + ("?" + queryParams))
                                + BasicCustomAuthenticatorConstants.FAILED_USERNAME + URLEncoder
                                .encode(request.getParameter(BasicCustomAuthenticatorConstants.USER_NAME),
                                        BasicCustomAuthenticatorConstants.UTF_8)
                                + BasicCustomAuthenticatorConstants.ERROR_CODE + errorCode
                                + BasicCustomAuthenticatorConstants.AUTHENTICATORS + getName() + ":"
                                + BasicCustomAuthenticatorConstants.LOCAL + retryParam;
                        response.sendRedirect(redirectURL);
                    } else {
                        retryParam = retryParam + BasicCustomAuthenticatorConstants.ERROR_CODE + errorCode
                                + BasicCustomAuthenticatorConstants.FAILED_USERNAME + URLEncoder
                                .encode(request.getParameter(BasicCustomAuthenticatorConstants.USER_NAME),
                                        BasicCustomAuthenticatorConstants.UTF_8);
                        response.sendRedirect(response.encodeRedirectURL(loginPage + ("?" + queryParams))
                                + BasicCustomAuthenticatorConstants.AUTHENTICATORS + getName() + ":"
                                + BasicCustomAuthenticatorConstants.LOCAL + retryParam);
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Unknown identity error code.");
                    }
                    response.sendRedirect(response.encodeRedirectURL(loginPage + ("?" + queryParams))
                            + BasicCustomAuthenticatorConstants.AUTHENTICATORS + getName() + ":"
                            + BasicCustomAuthenticatorConstants.LOCAL + retryParam);

                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Identity error message context is null");
                }
                response.sendRedirect(response.encodeRedirectURL(loginPage + ("?" + queryParams))
                        + BasicCustomAuthenticatorConstants.AUTHENTICATORS + getName() + ":"
                        + BasicCustomAuthenticatorConstants.LOCAL + retryParam);
            }

        } catch (IOException e) {
            throw new AuthenticationFailedException(e.getMessage(),
                    User.getUserFromUserName(request.getParameter(BasicCustomAuthenticatorConstants.USER_NAME)), e);
        }
    }

    @Override protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
            AuthenticationContext context) throws AuthenticationFailedException {

        String username = request.getParameter(BasicCustomAuthenticatorConstants.USER_NAME);
        String password = request.getParameter(BasicCustomAuthenticatorConstants.PASSWORD);

        Map<String, Object> authProperties = context.getProperties();
        if (authProperties == null) {
            authProperties = new HashMap<String, Object>();
            context.setProperties(authProperties);
        }

        authProperties.put(PASSWORD_PROPERTY, password);

        boolean isAuthenticated;
        UserStoreManager userStoreManager;
        // Check the authentication
        try {
            int tenantId = IdentityTenantUtil.getTenantIdOfUser(username);
            UserRealm userRealm = BasicCustomAuthenticatorServiceComponent.getRealmService()
                    .getTenantUserRealm(tenantId);
            if (userRealm != null) {
                userStoreManager = (UserStoreManager) userRealm.getUserStoreManager();
                isAuthenticated = userStoreManager
                        .authenticate(MultitenantUtils.getTenantAwareUsername(username), password);
            } else {
                throw new AuthenticationFailedException("Cannot find the user realm for the given tenant: " + tenantId,
                        User.getUserFromUserName(username));
            }
        } catch (IdentityRuntimeException e) {
            if (log.isDebugEnabled()) {
                log.debug("BasicAuthentication failed while trying to get the tenant ID of the user " + username, e);
            }
            throw new AuthenticationFailedException(e.getMessage(), User.getUserFromUserName(username), e);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            if (log.isDebugEnabled()) {
                log.debug("BasicAuthentication failed while trying to authenticate", e);
            }
            throw new AuthenticationFailedException(e.getMessage(), User.getUserFromUserName(username), e);
        }

        if (!isAuthenticated) {
            if (log.isDebugEnabled()) {
                log.debug("User authentication failed due to invalid credentials");
            }
            if (IdentityUtil.threadLocalProperties.get().get(RE_CAPTCHA_USER_DOMAIN) != null) {
                username = IdentityUtil.addDomainToName(username,
                        IdentityUtil.threadLocalProperties.get().get(RE_CAPTCHA_USER_DOMAIN).toString());
            }
            IdentityUtil.threadLocalProperties.get().remove(RE_CAPTCHA_USER_DOMAIN);
            throw new InvalidCredentialsException("User authentication failed due to invalid credentials",
                    User.getUserFromUserName(username));
        }

        String tenantDomain = MultitenantUtils.getTenantDomain(username);

        //TODO: user tenant domain has to be an attribute in the AuthenticationContext
        authProperties.put("user-tenant-domain", tenantDomain);

        username = FrameworkUtils.prependUserStoreDomainToName(username);

        if (getAuthenticatorConfig().getParameterMap() != null) {
            String userNameUri = getAuthenticatorConfig().getParameterMap().get("UserNameAttributeClaimUri");
            if (userNameUri != null && userNameUri.trim().length() > 0) {
                boolean multipleAttributeEnable;
                String domain = UserCoreUtil.getDomainFromThreadLocal();
                if (domain != null && domain.trim().length() > 0) {
                    multipleAttributeEnable = Boolean
                            .parseBoolean(userStoreManager.getSecondaryUserStoreManager(domain).
                                    getRealmConfiguration().getUserStoreProperty("MultipleAttributeEnable"));
                } else {
                    multipleAttributeEnable = Boolean.parseBoolean(userStoreManager.
                            getRealmConfiguration().getUserStoreProperty("MultipleAttributeEnable"));
                }
                if (multipleAttributeEnable) {
                    try {
                        if (log.isDebugEnabled()) {
                            log.debug("Searching for UserNameAttribute value for user " + username + " for claim uri : "
                                    + userNameUri);
                        }
                        String usernameValue = userStoreManager.
                                getUserClaimValue(MultitenantUtils.getTenantAwareUsername(username), userNameUri, null);
                        if (usernameValue != null && usernameValue.trim().length() > 0) {
                            tenantDomain = MultitenantUtils.getTenantDomain(username);
                            usernameValue = FrameworkUtils.prependUserStoreDomainToName(usernameValue);
                            username = usernameValue + "@" + tenantDomain;
                            if (log.isDebugEnabled()) {
                                log.debug("UserNameAttribute is found for user. Value is :  " + username);
                            }
                        }
                    } catch (UserStoreException e) {
                        //ignore  but log in debug
                        if (log.isDebugEnabled()) {
                            log.debug("Error while retrieving UserNameAttribute for user : " + username, e);
                        }
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("MultipleAttribute is not enabled for user store domain : " + domain + " "
                                + "Therefore UserNameAttribute is not retrieved");
                    }
                }
            }
        }
        context.setSubject(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username));
        String rememberMe = request.getParameter("chkRemember");

        if (rememberMe != null && "on".equals(rememberMe)) {
            context.setRememberMe(true);
        }
    }

    @Override protected boolean retryAuthenticationEnabled() {
        return true;
    }

    @Override public String getContextIdentifier(HttpServletRequest request) {
        return request.getParameter("sessionDataKey");
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