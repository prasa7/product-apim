/*
 *Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *WSO2 Inc. licenses this file to you under the Apache License,
 *Version 2.0 (the "License"); you may not use this file except
 *in compliance with the License.
 *You may obtain a copy of the License at
 *
 *http://www.apache.org/licenses/LICENSE-2.0
 *
 *Unless required by applicable law or agreed to in writing,
 *software distributed under the License is distributed on an
 *"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *KIND, either express or implied.  See the License for the
 *specific language governing permissions and limitations
 *under the License.
 */

package org.wso2.am.integration.tests.jwt;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.am.integration.clients.store.api.v1.dto.APIKeyDTO;
import org.wso2.am.integration.clients.store.api.v1.dto.ApplicationDTO;
import org.wso2.am.integration.clients.store.api.v1.dto.ApplicationKeyGenerateRequestDTO;
import org.wso2.am.integration.test.utils.APIManagerIntegrationTestException;
import org.wso2.am.integration.test.utils.base.APIMIntegrationConstants;
import org.wso2.am.integration.test.utils.bean.APIRequest;
import org.wso2.am.integration.tests.api.lifecycle.APIManagerLifecycleBaseTest;
import org.wso2.carbon.automation.engine.context.TestUserMode;
import org.wso2.carbon.automation.test.utils.http.client.HttpRequestUtil;
import org.wso2.carbon.automation.test.utils.http.client.HttpResponse;

import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.ws.rs.core.Response;

import static org.testng.Assert.assertNotNull;

public class APIKeyTestCase extends APIManagerLifecycleBaseTest {
    private static final Log log = LogFactory.getLog(APIKeyTestCase.class);

    private final String apiName = "APIKeyTestAPI";
    private final String apiContext = "apiKeyTest";
    private final String apiVersion = "1.0.0";
    private final String apiKeyApplicationName = "APIKeyApplication";
    private final String apiEndpointResource = "/customers/123";

    private String apiProvider;
    private String endpointURL;
    private String apiKeyApplicationId;
    private String apiId;
    private String apiInvocationUrl;

    @BeforeClass(alwaysRun = true)
    public void setEnvironment() throws Exception {
        super.init(TestUserMode.SUPER_TENANT_ADMIN);
        apiProvider = user.getUserName();
        endpointURL = getGatewayURLHttp() + "jaxrs_basic/services/customers/customerservice";
        apiInvocationUrl = getAPIInvocationURLHttp(apiContext + "/" + apiVersion + apiEndpointResource);
        org.wso2.carbon.automation.test.utils.http.client.HttpResponse applicationDTO =
                restAPIStore.createApplication(apiKeyApplicationName, "API Key Application",
                        APIMIntegrationConstants.APPLICATION_TIER.DEFAULT_APP_POLICY_FIFTY_REQ_PER_MIN,
                        ApplicationDTO.TokenTypeEnum.JWT);
        apiKeyApplicationId = applicationDTO.getData();

        APIRequest apiRequest = new APIRequest(apiName, apiContext, new URL(endpointURL));
        apiRequest.setVersion(apiVersion);
        apiRequest.setVisibility("public");
        apiRequest.setProvider(apiProvider);

        List<String> securitySchemes = new ArrayList<>();
        securitySchemes.add("api_key");
        securitySchemes.add("oauth2");
        apiRequest.setSecurityScheme(securitySchemes);

        apiId = createAndPublishAPIUsingRest(apiRequest, restAPIPublisher, false);
        waitForAPIDeploymentSync(user.getUserName(), apiName, apiVersion,
                APIMIntegrationConstants.IS_API_EXISTS);
        restAPIStore.subscribeToAPI(apiId, apiKeyApplicationId, TIER_GOLD);
    }

    @Test(groups = {"wso2.am"}, description = "Test API Invocation using API Key")
    public void testAPIInvocationUsingValidAPIKey() throws Exception {
        APIKeyDTO apiKeyDTO = restAPIStore.generateAPIKeys(apiKeyApplicationId,
                ApplicationKeyGenerateRequestDTO.KeyTypeEnum.PRODUCTION.toString(), -1, null, null);
        assertNotNull(apiKeyDTO, "API Key generation failed");
        log.info("Generated API Key == " + apiKeyDTO.getApikey());

        Map<String, String> requestHeader = new HashMap<>();
        requestHeader.put("apikey", apiKeyDTO.getApikey());
        requestHeader.put("accept", "text/xml");
        HttpResponse response = HttpRequestUtil.doGet(apiInvocationUrl, requestHeader);
        Assert.assertEquals(response.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Response code mismatched when API invocation");
    }

    @Test(groups = {"wso2.am"}, description = "Test API Invocation using revoked API Key")
    public void testAPIInvocationUsingInValidAPIKey() throws Exception {
        APIKeyDTO apiKeyDTO = restAPIStore.generateAPIKeys(apiKeyApplicationId,
                ApplicationKeyGenerateRequestDTO.KeyTypeEnum.PRODUCTION.toString(), -1, null, null);
        assertNotNull(apiKeyDTO, "API Key generation failed");
        log.info("Generated API Key ==" + apiKeyDTO.getApikey());

        restAPIStore.revokeAPIKey(apiKeyApplicationId, apiKeyDTO.getApikey());
        log.info("Successfully revoked the Key == " + apiKeyDTO.getApikey());

        Map<String, String> requestHeader = new HashMap<>();
        requestHeader.put("apikey", apiKeyDTO.getApikey());

        boolean isApiKeyValid = true;
        HttpResponse invocationResponseAfterRevoked;
        int counter = 1;
        do {
            // Wait while the JMS message is received to the related JMS topic
            Thread.sleep(1000L);
            invocationResponseAfterRevoked = HttpRequestUtil.doGet(apiInvocationUrl, requestHeader);
            int responseCodeAfterRevoked = invocationResponseAfterRevoked.getResponseCode();

            if (responseCodeAfterRevoked == HTTP_RESPONSE_CODE_UNAUTHORIZED) {
                isApiKeyValid = false;
            } else if (responseCodeAfterRevoked == HTTP_RESPONSE_CODE_OK) {
                isApiKeyValid = true;
            } else {
                throw new APIManagerIntegrationTestException("Unexpected response received when invoking the API. " +
                        "Response received :" + invocationResponseAfterRevoked.getData() + ":" +
                        invocationResponseAfterRevoked.getResponseMessage());
            }
            counter++;
        } while (isApiKeyValid && counter < 20);
        Assert.assertFalse(isApiKeyValid, "API Key revocation failed. " +
                "API invocation response code is expected to be : " + HTTP_RESPONSE_CODE_UNAUTHORIZED +
                ", but got " + invocationResponseAfterRevoked.getResponseCode());
    }

    @AfterClass(alwaysRun = true)
    public void destroy() throws Exception {
        restAPIStore.deleteApplication(apiKeyApplicationId);
        restAPIPublisher.deleteAPI(apiId);
    }
}
