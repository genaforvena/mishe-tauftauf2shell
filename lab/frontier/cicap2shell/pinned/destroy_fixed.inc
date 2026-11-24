void destroy_request(ci_request_t * req)
{
    int i;
    assert(req);
    for (i = 0; i < 5 && req->entities[i] != NULL; i++) {
        destroy_encaps_entity(req->entities[i]);
        req->entities[i] = NULL;
    }

    for (i = 0; i < 7; i++) {
        if (req->trash_entities[i])
            destroy_encaps_entity(req->trash_entities[i]);
    }
    free(req);
}
