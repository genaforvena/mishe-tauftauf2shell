int32_t analyze_server_response(int32_t s) {
  int32_t runs = 0;

  redirected_flag = 0;
  auth_flag = 0;
  while ((buf = hydra_receive_line(s)) != NULL) {
    runs++;
    // check for http redirection
    if (strstr(buf, "HTTP/1.1 3") != NULL || strstr(buf, "HTTP/1.0 3") != NULL || strstr(buf, "Status: 3") != NULL) {
      redirected_flag = 1;
    } else if (strstr(buf, "HTTP/1.1 401") != NULL || strstr(buf, "HTTP/1.0 401") != NULL) {
      auth_flag = 1;
    } else if ((strstr(buf, "HTTP/1.1 403") != NULL) || (strstr(buf, "HTTP/1.1 404") != NULL) || (strstr(buf, "HTTP/1.0 403") != NULL) || (strstr(buf, "HTTP/1.0 404") != NULL)) {
      return -1;
    }

    if (hydra_strcasestr(buf, "Location: ") != NULL) {
      char *startloc, *endloc;
      char str[2048];

      startloc = hydra_strcasestr(buf, "Location: ") + strlen("Location: ");
      strncpy(str, startloc, sizeof(str) - 1);
      str[sizeof(str) - 1] = 0;
      endloc = strchr(str, '\n');
      if (endloc != NULL)
        *endloc = 0;
      endloc = strchr(str, '\r');
      if (endloc != NULL)
        *endloc = 0;
      strcpy(redirected_url_buff, str);
    }
    // there can be multiple cookies
    if (hydra_strcasestr(buf, "Set-Cookie: ") != NULL) {
      char *cookiebuf = buf;

      do {
        char *startcookie, *endcookie1, *endcookie2;
        char str[1024], tmpcookie[4096] = "", tmpname[128] = "", *ptr, *ptr2;

        memset(str, 0, sizeof(str));
        startcookie = hydra_strcasestr(cookiebuf, "Set-Cookie: ") + strlen("Set-Cookie: ");
        strncpy(str, startcookie, sizeof(str) - 1);
        str[sizeof(str) - 1] = 0;
        endcookie1 = strchr(str, '\n');
        endcookie2 = strchr(str, ';');
        // terminate string after cookie data
        if (endcookie1 != NULL && ((endcookie1 < endcookie2) || (endcookie2 == NULL))) {
          if (*(endcookie1 - 1) == '\r')
            endcookie1--;
          *endcookie1 = 0;
        } else if (endcookie2 != NULL)
          *endcookie2 = 0;
        // is the cookie already there? if yes, remove it!
        if (strchr(startcookie, '=') != NULL && (ptr = strchr(startcookie, '=')) - startcookie + 1 <= sizeof(tmpname)) {
          strncpy(tmpname, startcookie, sizeof(tmpname) - 2);
          tmpname[sizeof(tmpname) - 2] = 0;
          ptr = strchr(tmpname, '=');
          if (ptr) *(++ptr) = 0;
          // is the cookie already in the cookiejar? (so, does it have to be
          // replaced?)
          if ((ptr = hydra_strcasestr(cookie, tmpname)) != NULL) {
            // yes it is.
            // if the cookie is not in the beginning of the cookiejar, copy the
            // ones before
            if (ptr != cookie && *(ptr - 1) == ' ') {
              ssize_t off = ptr - cookie - 2;
              if (off > 0) {
                size_t n = (size_t)off;
                if (n >= sizeof(tmpcookie)) n = sizeof(tmpcookie) - 1;
                strncpy(tmpcookie, cookie, n);
                tmpcookie[n] = 0;
              }
            }
            ptr += strlen(tmpname);
            // if there are any cookies after this one in the cookiejar, copy
            // them over
            if ((ptr2 = strstr(ptr, "; ")) != NULL) {
              ptr2 += 2;
              strncat(tmpcookie, ptr2, sizeof(tmpcookie) - strlen(tmpcookie) - 1);
            }
            if (debug)
              printf("[DEBUG] removing cookie %s in jar\n before: %s\n after:  "
                     "%s\n",
                     tmpname, cookie, tmpcookie);
            strcpy(cookie, tmpcookie);
          }
        }
        ptr = strchr(str, '=');
        // only copy the cookie if it has a value (otherwise the server wants to
        // delete the cookie)
        if (ptr != NULL && *(ptr + 1) != ';' && *(ptr + 1) != 0 && *(ptr + 1) != '\n' && *(ptr + 1) != '\r') {
          if (strlen(cookie) > 0)
            strncat(cookie, "; ", sizeof(cookie) - strlen(cookie) - 1);
          strncat(cookie, str, sizeof(cookie) - strlen(cookie) - 1);
        }
        cookiebuf = startcookie;
      } while (hydra_strcasestr(cookiebuf, "Set-Cookie: ") != NULL);
    }
#ifdef HAVE_PCRE
    if (hydra_string_match(buf, cond) == 1) {
#else
    if (strstr(buf, cond) != NULL) {
#endif
      free(buf);
      //      printf("DEBUG: STRING %s FOUND!!:\n%s\n", cond, buf);
      return 1;
    }
    //    else printf("DEBUG: STRING %s NOT FOUND:\n%s\n", cond, buf);
    free(buf);
  }
  if (runs == 0) {
    if (debug)
      hydra_report(stderr, "DEBUG: no response from server\n");
    return -1;
  }
  return 0;
}
