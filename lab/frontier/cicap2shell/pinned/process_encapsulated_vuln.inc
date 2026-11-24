int process_encapsulated(ci_request_t * req, const char *buf)
{
    const char *start;
    const char *pos;
    char *end;
    int type = 0, num = 0, val = 0;
    int hasbody = 1;           /*Assume that we have a resbody or reqbody or optbody */
    start = buf + 13; /*strlen("Encapsulated:")*/
    pos = start;
    end = (char *)start;
    for (; isspace((int)*pos) && *pos != '\0'; ++pos);
    while (*pos != '\0') {
        type = get_encaps_type(pos, &val, &end);
        if (type < 0) /*parse error - return "400 bad request"*/
            return EC_400;
        if (num > 5)          /*In practice there is an error here .... */
            break;
        if (type == ICAP_NULL_BODY)
            hasbody = 0;     /*We have not a body */
        req->entities[num++] = ci_request_alloc_entity(req, type, val);

        assert(start != end);
        pos = end;            /* points after the value of entity.... */
        for (; (isspace((int)*pos) || *pos == ',') && *pos != '\0'; ++pos);
    }
    req->hasbody = hasbody;
    return EC_100;
}
